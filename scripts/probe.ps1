param(
    [Parameter(Mandatory=$true)][string]$TargetHost,
    [Parameter(Mandatory=$true)][string]$Command
)

$ErrorActionPreference = 'Stop'
$bin = "$PSScriptRoot\..\target\release\fast-mcp-ssh.exe"
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $bin; $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true
$psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
$proc = [System.Diagnostics.Process]::Start($psi); $stdin = $proc.StandardInput; $stdout = $proc.StandardOutput
function S($f) { $stdin.WriteLine((ConvertTo-Json $f -Compress -Depth 10)); $stdin.Flush() }
function Recv { $tk = $stdout.ReadLineAsync(); if ($tk.Wait(15000)) { $tk.Result } else { '<timeout>' } }
S @{ jsonrpc='2.0'; id=1; method='initialize'; params=@{ protocolVersion='2024-11-05'; capabilities=@{}; clientInfo=@{ name='probe'; version='1' } } }
$null = Recv; S @{ jsonrpc='2.0'; method='notifications/initialized' }

S @{ jsonrpc='2.0'; id=2; method='tools/call'; params=@{ name='exec'; arguments=@{ host=$TargetHost; cmd=$Command; timeout=15 } } }
Write-Host (Recv)

$stdin.Close(); $proc.WaitForExit(3000) | Out-Null
