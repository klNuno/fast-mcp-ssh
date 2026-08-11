//! One confirmation path, two protocol eras.
//!
//! Up to `2025-11-25` a server could open an `elicitation/create` request and
//! await the answer where it stood. From `2026-07-28` servers no longer
//! initiate requests (SEP-2322): the tool returns an `InputRequiredResult`
//! carrying what it needs, the client answers it, then retries the same call
//! with the answers in `inputResponses`. Both shapes live here so no tool has
//! to know which era its caller belongs to.
//!
//! The retry re-runs the tool from its first line, so every caller must ask
//! before it touches the remote host. That already holds: confirmation guards
//! a command, and the guard runs before the connection is opened.

use std::collections::BTreeMap;

use rmcp::RoleServer;
use rmcp::model::{
    ElicitRequest, ElicitRequestParams, ElicitResult, ElicitationAction, ElicitationSchema,
    InputRequest, InputRequests, InputRequiredResult, ProtocolVersion,
};
use rmcp::service::RequestContext;
use serde_json::Value;

use crate::server::ConfirmElicit;

/// What a caller learned from asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// The user said yes.
    Approved,
    /// The user said no, cancelled, or the ask never made it through. Every
    /// non-yes collapses here: confirmation fails closed.
    Denied,
    /// The ask was queued for the client and no answer exists yet. The caller
    /// must stop and hand [`Confirm::into_input_required`] back instead of
    /// doing the work.
    Deferred,
}

/// Collects the confirmations one tool call needs.
pub(crate) struct Confirm<'a> {
    ctx: &'a RequestContext<RoleServer>,
    /// True once the peer negotiated a revision where the server may no longer
    /// initiate requests.
    multi_round: bool,
    /// Answers echoed back by the client on a retry, keyed as the previous
    /// round keyed its requests.
    answers: BTreeMap<String, Value>,
    /// Asks queued for this round.
    pending: InputRequests,
}

impl<'a> Confirm<'a> {
    pub(crate) fn new(
        ctx: &'a RequestContext<RoleServer>,
        answers: Option<BTreeMap<String, Value>>,
    ) -> Self {
        let multi_round = ctx
            .protocol_version()
            .is_some_and(|v| v >= ProtocolVersion::V_2026_07_28);
        Self {
            ctx,
            multi_round,
            answers: answers.unwrap_or_default(),
            pending: InputRequests::new(),
        }
    }

    /// Asks for a yes on `key`, or reports the answer a previous round already
    /// produced. `key` must be derived from what is being confirmed, not from
    /// call order: the retry re-runs the same code and has to land on the same
    /// key to find its answer. See [`key_for`].
    pub(crate) async fn ask(&mut self, key: &str, prompt: &str) -> Answer {
        if !self.multi_round {
            return match crate::server::elicit_confirmation(self.ctx, prompt).await {
                Ok(true) => Answer::Approved,
                Ok(false) => Answer::Denied,
                Err(e) => {
                    tracing::warn!(?e, "elicitation failed; defaulting to deny (fail-closed)");
                    Answer::Denied
                }
            };
        }
        if let Some(answer) = answer_for(&self.answers, key) {
            return answer;
        }
        if !self.pending.contains_key(key) {
            match elicit_request(prompt) {
                Ok(request) => {
                    drop(self.pending.insert(key.to_string(), request));
                }
                Err(e) => {
                    tracing::warn!(?e, "cannot build elicitation request; deny (fail-closed)");
                    return Answer::Denied;
                }
            }
        }
        Answer::Deferred
    }

    /// True once at least one ask was queued for the client.
    pub(crate) fn deferred(&self) -> bool {
        !self.pending.is_empty()
    }

    /// The interim result to return in place of the tool's own. `request_state`
    /// stays empty on purpose: this server holds no cross-round state, every
    /// key is re-derived from the retried arguments, and the spec is satisfied
    /// by `inputRequests` alone.
    pub(crate) fn into_input_required(self) -> InputRequiredResult {
        InputRequiredResult::from_input_requests(self.pending)
    }
}

/// The answer a previous round produced for `key`, or `None` when the client
/// has not been asked yet. Reads without removing: a batch may reach the same
/// key from several commands and each of them has to see the same answer.
fn answer_for(answers: &BTreeMap<String, Value>, key: &str) -> Option<Answer> {
    let raw = answers.get(key)?;
    match serde_json::from_value::<ElicitResult>(raw.clone()) {
        Ok(result) => Some(yes_from(&result)),
        Err(e) => {
            tracing::warn!(?e, "unparseable elicitation answer; deny (fail-closed)");
            Some(Answer::Denied)
        }
    }
}

fn yes_from(result: &ElicitResult) -> Answer {
    if result.action != ElicitationAction::Accept {
        return Answer::Denied;
    }
    let approved = result
        .content
        .clone()
        .and_then(|c| serde_json::from_value::<ConfirmElicit>(c).ok())
        .is_some_and(|c| c.answer.trim().eq_ignore_ascii_case("yes"));
    if approved {
        Answer::Approved
    } else {
        Answer::Denied
    }
}

fn elicit_request(prompt: &str) -> Result<InputRequest, rmcp::ErrorData> {
    let requested_schema = ElicitationSchema::from_type::<ConfirmElicit>()
        .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;
    Ok(InputRequest::Elicitation(ElicitRequest::new(
        ElicitRequestParams::FormElicitationParams {
            meta: None,
            message: prompt.to_string(),
            requested_schema,
        },
    )))
}

/// A key for what is being confirmed. Stable across rounds because it is a
/// pure function of `parts`, which the retry rebuilds from the same arguments.
pub(crate) fn key_for(parts: &[&str]) -> String {
    // FNV-1a rather than DefaultHasher: the latter is only documented as
    // deterministic within one Rust version, and this key is compared across
    // round trips.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            hash = mix(hash, 0);
        }
        for byte in part.as_bytes() {
            hash = mix(hash, *byte);
        }
    }
    format!("confirm-{hash:016x}")
}

const fn mix(hash: u64, byte: u8) -> u64 {
    (hash ^ byte as u64).wrapping_mul(0x0000_0100_0000_01b3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_stable_and_field_separated() {
        assert_eq!(key_for(&["web", "rm -rf /"]), key_for(&["web", "rm -rf /"]));
        // Without a separator these two would collide.
        assert_ne!(key_for(&["ab", "c"]), key_for(&["a", "bc"]));
    }

    #[test]
    fn an_unasked_key_has_no_answer_and_garbage_denies() {
        let mut answers = BTreeMap::new();
        drop(answers.insert(
            "k".to_string(),
            serde_json::json!({ "not": "an elicit result" }),
        ));
        assert_eq!(answer_for(&answers, "other"), None);
        assert_eq!(answer_for(&answers, "k"), Some(Answer::Denied));
    }

    #[test]
    fn a_queued_ask_is_a_form_elicitation_the_client_can_answer() {
        let queued = elicit_request("delete everything?").expect("schema builds");
        let wire = serde_json::to_value(InputRequiredResult::from_input_requests(
            [("k".to_string(), queued)].into_iter().collect(),
        ))
        .expect("serializes");
        assert_eq!(wire["resultType"], "input_required");
        let request = &wire["inputRequests"]["k"];
        assert_eq!(request["method"], "elicitation/create");
        assert_eq!(request["params"]["mode"], "form");
        assert_eq!(request["params"]["message"], "delete everything?");
        // The schema is what tells the client to collect the `answer` field
        // this server then matches against "yes".
        assert!(request["params"]["requestedSchema"]["properties"]["answer"].is_object());
    }

    #[test]
    fn only_an_accepted_yes_approves() {
        let accept = |answer: &str| {
            ElicitResult::new(ElicitationAction::Accept)
                .with_content(serde_json::json!({ "answer": answer }))
        };
        assert_eq!(yes_from(&accept("yes")), Answer::Approved);
        assert_eq!(yes_from(&accept("  YES \n")), Answer::Approved);
        assert_eq!(yes_from(&accept("no")), Answer::Denied);
        assert_eq!(yes_from(&accept("")), Answer::Denied);
        // Accepted with no content at all is not a yes.
        assert_eq!(
            yes_from(&ElicitResult::new(ElicitationAction::Accept)),
            Answer::Denied
        );
        // A decline carrying a "yes" payload is still a no.
        assert_eq!(
            yes_from(
                &ElicitResult::new(ElicitationAction::Decline)
                    .with_content(serde_json::json!({ "answer": "yes" }))
            ),
            Answer::Denied
        );
        assert_eq!(
            yes_from(&ElicitResult::new(ElicitationAction::Cancel)),
            Answer::Denied
        );
    }
}
