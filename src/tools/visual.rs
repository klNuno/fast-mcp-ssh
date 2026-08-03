//! Visual tools: `shot`.
//!
//! A screenshot is the one remote observation that cannot be reduced to text,
//! and it is also the most expensive thing this server can put in front of a
//! model: a raw 1080p PNG is a few megabytes, and every pixel costs tokens. So
//! the capture is downscaled and re-encoded here, on the operator's machine,
//! before it ever becomes an `ImageContent` block, and `local=` writes the
//! untouched original to disk instead of returning it at all.

use std::io::Cursor;
use std::time::Duration;

use base64::Engine;
use image::ImageFormat;
use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::*, schemars, tool,
    tool_router,
};
use serde::Deserialize;

use crate::audit::AuditRecord;
use crate::errors::SshError;
use crate::guards;
use crate::output::Toon;
use crate::server::SshServer;
use crate::session::exec;
use crate::sftp;
use crate::tools::shell_quote;

/// Widest image handed back to the model unless the caller says otherwise.
/// Image tokens scale with area, so halving this quarters the cost; 1024 is
/// about where a desktop is still readable.
const DEFAULT_MAX_WIDTH: u32 = 1024;
const MAX_MAX_WIDTH: u32 = 3840;
const DEFAULT_QUALITY: u8 = 75;
/// Refuse a capture that arrives absurdly large rather than spend a minute
/// decoding it. A 4K PNG screenshot lands around 10 MB.
const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ShotFormat {
    /// Lossy, small. The default, and what a screenshot should be.
    Jpeg,
    /// Lossless, several times larger. For pixel-exact reads.
    Png,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ShotArgs {
    /// Host alias. Omit if a default_host is configured.
    #[serde(default)]
    pub host: Option<String>,
    /// X11 display to capture. Default ":0". Ignored on Wayland backends.
    #[serde(default)]
    pub display: Option<String>,
    /// Local path for the full-resolution original. Set it to keep the image
    /// out of the reply entirely.
    #[serde(default)]
    pub local: Option<String>,
    /// Widest edge of the returned image, in pixels. Default 1024, max 3840.
    #[serde(default)]
    pub max_width: Option<u32>,
    /// Returned encoding: "jpeg" (default) or "png".
    #[serde(default)]
    pub format: Option<ShotFormat>,
    /// JPEG quality 1-100. Default 75. Ignored for png.
    #[serde(default)]
    pub quality: Option<u8>,
}

/// A capture backend, in the order they are tried. Each entry is
/// `(binary, argv template, needs an X11 DISPLAY)`; `{}` is the output path,
/// already shell-quoted.
const BACKENDS: &[(&str, &str, bool)] = &[
    // Wayland/wlroots. Reads WAYLAND_DISPLAY, not DISPLAY.
    ("grim", "grim -t png {}", false),
    ("gnome-screenshot", "gnome-screenshot -f {}", true),
    ("spectacle", "spectacle -b -n -o {}", true),
    // ImageMagick. `import` is also the name of a Python tool, but the probe
    // only ever sees the one on PATH of a desktop session.
    ("import", "import -window root {}", true),
    ("scrot", "scrot -o {}", true),
];

#[tool_router(router = visual_router, vis = "pub")]
impl SshServer {
    #[tool(
        description = "Screenshot the remote desktop and return it as an image. Downscaled before it reaches you; local=<path> writes the original to disk instead. Needs a graphical session.",
        annotations(
            title = "Shot",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn shot(
        &self,
        Parameters(args): Parameters<ShotArgs>,
    ) -> Result<CallToolResult, McpError> {
        let host_name = self.resolve_host(args.host)?;
        // Remote-controlled bytes landing on the operator's filesystem, same
        // rule as `dn`.
        let local_path = args.local.as_deref().map(guards::resolve_local_path);
        if let Some(p) = local_path.as_deref()
            && let Err(e) = guards::check_local_write(p)
        {
            let reason = e.to_string();
            self.audit.write(
                &host_name,
                "shot",
                AuditRecord {
                    cmd: args.local.as_deref(),
                    blocked: Some(&reason),
                    error: Some(reason.clone()),
                    ..Default::default()
                },
            );
            return Err(e.into_mcp());
        }

        let facts = self.host_facts(&host_name, false).await?;
        let (bin, template, needs_display) = BACKENDS
            .iter()
            .find(|(bin, _, _)| facts.has(bin))
            .ok_or_else(|| {
                SshError::Other(format!(
                    "no screenshot backend on {host_name}: none of {} are installed",
                    BACKENDS
                        .iter()
                        .map(|(b, _, _)| *b)
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
                .into_mcp()
            })?;

        let session = self
            .pool
            .get_or_connect(&host_name, None)
            .await
            .map_err(|e| e.into_mcp())?;

        // Capture to a private temp file rather than to stdout: half these
        // tools refuse a non-seekable output, and the ones that accept `-`
        // still interleave their own warnings into it.
        let remote = format!("/tmp/.fast-mcp-ssh-shot-{}.png", nonce());
        let quoted = shell_quote(&remote);
        let display = args.display.as_deref().unwrap_or(":0");
        let env = if *needs_display {
            format!("DISPLAY={} ", shell_quote(display))
        } else {
            // wlroots compositors want the runtime dir, which a non-login SSH
            // session does not inherit.
            "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)} ".to_string()
        };
        let cmd = format!("{env}{}", template.replace("{}", &quoted));

        let r = exec::exec(
            &session,
            &cmd,
            Duration::from_secs(30),
            self.cfg().defaults.max_capture_bytes,
        )
        .await
        .map_err(|e| e.into_mcp())?;
        if r.exit_code != 0 {
            let _ = sftp::remove(&session, &remote, false).await;
            return Err(SshError::Other(format!(
                "{bin} failed on {host_name} (exit {}): {}",
                r.exit_code,
                r.stderr.trim()
            ))
            .into_mcp());
        }

        let fetched =
            sftp::download(&session, &remote, local_path.as_deref(), MAX_CAPTURE_BYTES).await;
        // The temp file goes whether or not the fetch worked.
        let _ = sftp::remove(&session, &remote, false).await;
        let (transfer, raw) = fetched.map_err(|e| e.into_mcp())?;

        let mut t = Toon::new();
        t.field("host", &host_name)
            .field("backend", *bin)
            .field("bytes", transfer.bytes)
            .field("ms", transfer.duration_ms as u64);

        let Some(raw) = raw else {
            // `local=` was given, so the original is on disk and nothing is
            // worth putting in the reply.
            if let Some(p) = args.local.as_deref() {
                t.field("local", p);
            } else {
                t.field(
                    "error",
                    "capture exceeded the 64 MB cap; rerun with local=<path>",
                );
            }
            self.audit.write(
                &host_name,
                "shot",
                AuditRecord {
                    cmd: Some(&remote),
                    exit_code: Some(r.exit_code),
                    duration_ms: Some(transfer.duration_ms),
                    bytes_out: Some(transfer.bytes),
                    ..Default::default()
                },
            );
            return Ok(crate::tools::text(t.into_string()));
        };

        let max_width = args
            .max_width
            .unwrap_or(DEFAULT_MAX_WIDTH)
            .clamp(16, MAX_MAX_WIDTH);
        let format = args.format.unwrap_or(ShotFormat::Jpeg);
        let quality = args.quality.unwrap_or(DEFAULT_QUALITY).clamp(1, 100);
        // Decode, resize and re-encode are CPU-bound and the runtime is
        // current-thread: doing this inline would stall every other session.
        let encoded =
            tokio::task::spawn_blocking(move || downscale(&raw, max_width, format, quality))
                .await
                .map_err(|e| SshError::Other(format!("image worker: {e}")).into_mcp())?
                .map_err(|e| e.into_mcp())?;

        t.field("width", encoded.width as u64)
            .field("height", encoded.height as u64)
            .field(
                "format",
                if format == ShotFormat::Png {
                    "png"
                } else {
                    "jpeg"
                },
            )
            .field("image_bytes", encoded.data.len());
        self.audit.write(
            &host_name,
            "shot",
            AuditRecord {
                cmd: Some(&remote),
                exit_code: Some(r.exit_code),
                duration_ms: Some(transfer.duration_ms),
                bytes_out: Some(transfer.bytes),
                ..Default::default()
            },
        );
        let mime = if format == ShotFormat::Png {
            "image/png"
        } else {
            "image/jpeg"
        };
        Ok(CallToolResult::success(vec![
            ContentBlock::text(t.into_string()),
            ContentBlock::image(
                base64::engine::general_purpose::STANDARD.encode(&encoded.data),
                mime,
            ),
        ]))
    }
}

struct Encoded {
    data: Vec<u8>,
    width: u32,
    height: u32,
}

/// Decode a capture, fit it inside `max_width` and re-encode. Blocking: call it
/// from `spawn_blocking`.
fn downscale(
    raw: &[u8],
    max_width: u32,
    format: ShotFormat,
    quality: u8,
) -> crate::errors::Result<Encoded> {
    let img = image::load_from_memory(raw)
        .map_err(|e| SshError::Other(format!("cannot decode the capture: {e}")))?;
    // Triangle, not Lanczos3: this is a screenshot being shrunk for a model to
    // read, and Lanczos costs several times more for ringing around text.
    let img = if img.width() > max_width {
        let height = ((img.height() as u64 * max_width as u64) / img.width() as u64).max(1) as u32;
        img.resize_exact(max_width, height, image::imageops::FilterType::Triangle)
    } else {
        img
    };
    let (width, height) = (img.width(), img.height());
    let mut data = Vec::new();
    match format {
        ShotFormat::Png => img
            .write_to(&mut Cursor::new(&mut data), ImageFormat::Png)
            .map_err(|e| SshError::Other(format!("cannot encode png: {e}")))?,
        ShotFormat::Jpeg => {
            // JPEG has no alpha, and the encoder errors instead of dropping it.
            let rgb = img.to_rgb8();
            let mut enc =
                image::codecs::jpeg::JpegEncoder::new_with_quality(Cursor::new(&mut data), quality);
            enc.encode_image(&rgb)
                .map_err(|e| SshError::Other(format!("cannot encode jpeg: {e}")))?;
        }
    }
    Ok(Encoded {
        data,
        width,
        height,
    })
}

/// Hex nonce for the remote temp path, so two concurrent `shot` calls on one
/// host cannot overwrite each other's capture.
fn nonce() -> String {
    let mut b = [0u8; 8];
    if getrandom::fill(&mut b).is_err() {
        // Only reached if the OS entropy source is unavailable; a collision
        // here costs a retry, not correctness.
        b = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0))
        .to_le_bytes();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(w: u32, h: u32) -> Vec<u8> {
        let img = image::RgbImage::from_fn(w, h, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, 128])
        });
        let mut out = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn downscale_fits_the_width_and_keeps_the_aspect() {
        let e = downscale(&png(1920, 1080), 1024, ShotFormat::Jpeg, 75).unwrap();
        assert_eq!(e.width, 1024);
        assert_eq!(e.height, 576);
        assert!(!e.data.is_empty());
    }

    #[test]
    fn downscale_never_upscales() {
        let e = downscale(&png(320, 200), 1024, ShotFormat::Png, 75).unwrap();
        assert_eq!((e.width, e.height), (320, 200));
    }

    #[test]
    fn lower_jpeg_quality_costs_fewer_bytes() {
        let raw = png(800, 600);
        let low = downscale(&raw, 800, ShotFormat::Jpeg, 10).unwrap();
        let high = downscale(&raw, 800, ShotFormat::Jpeg, 95).unwrap();
        assert!(low.data.len() < high.data.len());
    }

    #[test]
    fn a_capture_that_is_not_an_image_is_an_error() {
        assert!(downscale(b"not an image at all", 1024, ShotFormat::Jpeg, 75).is_err());
    }

    #[test]
    fn nonces_differ() {
        assert_ne!(nonce(), nonce());
    }

    #[test]
    fn every_backend_template_has_an_output_slot() {
        for (bin, template, _) in BACKENDS {
            assert!(template.contains("{}"), "{bin} has no output placeholder");
            assert!(
                template.starts_with(bin),
                "{bin} template runs something else"
            );
        }
    }

    #[test]
    fn every_backend_is_one_the_facts_probe_looks_for() {
        // Backend selection is `facts.has(bin)`. A backend the probe never
        // reports can never be chosen: `spectacle` sat in this list unusable,
        // so a KDE host got "no screenshot backend" with spectacle installed.
        let probe = crate::tools::ops::FACTS_PROBE;
        let listed: Vec<&str> = probe
            .lines()
            .find(|l| l.trim_start().starts_with("for c in "))
            .expect("probe has a `for c in` loop")
            .trim()
            .trim_start_matches("for c in ")
            .trim_end_matches("; do")
            .split_whitespace()
            .collect();
        for (bin, _, _) in BACKENDS {
            assert!(
                listed.contains(bin),
                "{bin} is a backend the facts probe never reports (probed: {listed:?})"
            );
        }
    }
}
