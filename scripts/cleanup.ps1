param(
    [string]$TargetHost = "target"
)

$ErrorActionPreference = 'Stop'
$bin = "$PSScriptRoot\..\target\release\fast-mcp-ssh.exe"
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $bin; $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true
$psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
$proc = [System.Diagnostics.Process]::Start($psi)
$stdin = $proc.StandardInput; $stdout = $proc.StandardOutput
function Send-Frame($f) { $stdin.WriteLine((ConvertTo-Json -InputObject $f -Compress -Depth 10)); $stdin.Flush() }
function Read-Response { $tk = $stdout.ReadLineAsync(); if ($tk.Wait(15000)) { $tk.Result } else { '<timeout>' } }
Send-Frame @{ jsonrpc='2.0'; id=1; method='initialize'; params=@{ protocolVersion='2024-11-05'; capabilities=@{}; clientInfo=@{ name='cleanup'; version='1' } } }
$null = Read-Response
Send-Frame @{ jsonrpc='2.0'; method='notifications/initialized' }
Send-Frame @{ jsonrpc='2.0'; id=2; method='tools/call'; params=@{ name='exec'; arguments=@{ host=$TargetHost; cmd='rm -f /tmp/fast-mcp-ssh-test.txt /tmp/dn-test.txt /tmp/post-sh.txt /tmp/sftp-debug.txt && echo cleaned'; timeout=5 } } }
Write-Host (Read-Response)
$stdin.Close(); $proc.WaitForExit(3000) | Out-Null
