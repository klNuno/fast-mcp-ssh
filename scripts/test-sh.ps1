# Tests sh (PTY persistent) + ping. Uses async pipes so server has time to respond.
# Pass a host alias from your hosts.toml as the first argument. Defaults to "target".

param(
    [string]$TargetHost = "target"
)

$ErrorActionPreference = 'Stop'
$bin = "$PSScriptRoot\..\target\release\fast-mcp-ssh.exe"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $bin
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

$proc = [System.Diagnostics.Process]::Start($psi)

$stderrJob = Start-Job -ScriptBlock {
    param($p)
    $p.StandardError.ReadToEnd()
} -ArgumentList $proc

$stdin = $proc.StandardInput
$stdout = $proc.StandardOutput

function Send-Frame($frame) {
    $json = ConvertTo-Json -InputObject $frame -Compress -Depth 10
    $stdin.WriteLine($json)
    $stdin.Flush()
}

function Read-Response {
    param([int]$timeoutSec = 30)
    $task = $stdout.ReadLineAsync()
    if (-not $task.Wait($timeoutSec * 1000)) {
        return "<timeout>"
    }
    return $task.Result
}

Send-Frame @{ jsonrpc='2.0'; id=1; method='initialize'; params=@{ protocolVersion='2024-11-05'; capabilities=@{}; clientInfo=@{ name='t'; version='0.1' } } }
$r = Read-Response 10
Write-Host "init -> $r"

Send-Frame @{ jsonrpc='2.0'; method='notifications/initialized' }

Send-Frame @{ jsonrpc='2.0'; id=2; method='tools/call'; params=@{ name='ping'; arguments=@{} } }
$r = Read-Response 30
Write-Host ""
Write-Host "=== ping (all hosts) ===" -ForegroundColor Green
Write-Host $r

Send-Frame @{ jsonrpc='2.0'; id=3; method='tools/call'; params=@{ name='sh'; arguments=@{ host=$TargetHost; cmd='cd /tmp && pwd && echo state-test-1'; timeout=20 } } }
$r = Read-Response 25
Write-Host ""
Write-Host "=== sh #1 (cd) ===" -ForegroundColor Green
Write-Host $r

Send-Frame @{ jsonrpc='2.0'; id=4; method='tools/call'; params=@{ name='sh'; arguments=@{ host=$TargetHost; cmd='pwd; echo persistence-check'; timeout=15 } } }
$r = Read-Response 20
Write-Host ""
Write-Host "=== sh #2 (pwd should be /tmp) ===" -ForegroundColor Green
Write-Host $r

Send-Frame @{ jsonrpc='2.0'; id=5; method='tools/call'; params=@{ name='wr'; arguments=@{ host=$TargetHost; remote='/tmp/fast-mcp-ssh-test.txt'; content="hello`nfrom`nmcp`n"; mode=420 } } }
$r = Read-Response 15
Write-Host ""
Write-Host "=== wr ===" -ForegroundColor Green
Write-Host $r

Send-Frame @{ jsonrpc='2.0'; id=6; method='tools/call'; params=@{ name='dn'; arguments=@{ host=$TargetHost; remote='/tmp/fast-mcp-ssh-test.txt' } } }
$r = Read-Response 15
Write-Host ""
Write-Host "=== dn (inline) ===" -ForegroundColor Green
Write-Host $r

Send-Frame @{ jsonrpc='2.0'; id=7; method='tools/call'; params=@{ name='tail'; arguments=@{ host=$TargetHost; path='/var/log/auth.log'; lines=5 } } }
$r = Read-Response 15
Write-Host ""
Write-Host "=== tail ===" -ForegroundColor Green
Write-Host $r

Send-Frame @{ jsonrpc='2.0'; id=8; method='tools/call'; params=@{ name='exec'; arguments=@{ host=$TargetHost; cmd='rm -rf /'; timeout=5 } } }
$r = Read-Response 10
Write-Host ""
Write-Host "=== guard (rm -rf /) ===" -ForegroundColor Green
Write-Host $r

$stdin.Close()
$proc.WaitForExit(5000) | Out-Null
if (-not $proc.HasExited) { $proc.Kill() }
Wait-Job $stderrJob | Out-Null
$err = Receive-Job $stderrJob
Remove-Job $stderrJob
Write-Host ""
Write-Host "=== STDERR ===" -ForegroundColor Yellow
Write-Host $err
