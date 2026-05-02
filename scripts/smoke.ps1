# Smoke test the MCP server end-to-end.
# Sends initialize, tools/list, and a few tools/call frames over stdio and prints JSON-RPC responses.
#
# Pass a host alias from your hosts.toml as the first argument.
# Defaults to "target".

param(
    [string]$TargetHost = "target"
)

$ErrorActionPreference = 'Stop'
$bin = Resolve-Path "$PSScriptRoot\..\target\release\fast-mcp-ssh.exe"

$frames = @(
    @{ jsonrpc='2.0'; id=1; method='initialize'; params=@{
        protocolVersion='2024-11-05'
        capabilities=@{}
        clientInfo=@{ name='smoke'; version='0.1' }
    }},
    @{ jsonrpc='2.0'; method='notifications/initialized' },
    @{ jsonrpc='2.0'; id=2; method='tools/list'; params=@{} },
    @{ jsonrpc='2.0'; id=3; method='tools/call'; params=@{ name='hosts'; arguments=@{} } },
    @{ jsonrpc='2.0'; id=4; method='tools/call'; params=@{ name='exec'; arguments=@{ host=$TargetHost; cmd='echo "hello from mcp"; uname -a; whoami'; timeout=15 } } },
    @{ jsonrpc='2.0'; id=5; method='tools/call'; params=@{ name='ls'; arguments=@{ host=$TargetHost; path='/etc' } } },
    @{ jsonrpc='2.0'; id=6; method='tools/call'; params=@{ name='sh'; arguments=@{ host=$TargetHost; cmd='cd /tmp && pwd && echo state-test'; timeout=15 } } },
    @{ jsonrpc='2.0'; id=7; method='tools/call'; params=@{ name='sh'; arguments=@{ host=$TargetHost; cmd='pwd'; timeout=15 } } },
    @{ jsonrpc='2.0'; id=8; method='tools/call'; params=@{ name='ping'; arguments=@{} } },
    @{ jsonrpc='2.0'; id=9; method='tools/call'; params=@{ name='disconnect'; arguments=@{ host=$TargetHost } } }
)

$payload = ($frames | ForEach-Object { ConvertTo-Json -InputObject $_ -Compress -Depth 10 }) -join "`n"
$payload += "`n"

Write-Host "=== Sending $($frames.Count) frames against host '$TargetHost' ===" -ForegroundColor Cyan
$tmpIn = New-TemporaryFile
$tmpOut = New-TemporaryFile
$tmpErr = New-TemporaryFile
[System.IO.File]::WriteAllText($tmpIn, $payload, [System.Text.UTF8Encoding]::new($false))

$proc = Start-Process -FilePath $bin -RedirectStandardInput $tmpIn -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr -PassThru -NoNewWindow
$null = $proc.WaitForExit(45000)
if (-not $proc.HasExited) {
    $proc.Kill()
    Write-Host "TIMEOUT - killed after 45s" -ForegroundColor Red
}

Write-Host "=== STDERR ===" -ForegroundColor Yellow
Get-Content $tmpErr | ForEach-Object { Write-Host $_ }

Write-Host ""
Write-Host "=== STDOUT (responses) ===" -ForegroundColor Green
Get-Content $tmpOut | ForEach-Object {
    try {
        $obj = $_ | ConvertFrom-Json
        if ($obj.id) {
            $idStr = [string]$obj.id
            Write-Host ('--- id=' + $idStr + ' ---') -ForegroundColor Magenta
        }
        $obj | ConvertTo-Json -Depth 12
    } catch {
        Write-Host $_
    }
}

Remove-Item $tmpIn, $tmpOut, $tmpErr -ErrorAction SilentlyContinue
