$ErrorActionPreference = 'Stop'

$router = '10.88.0.254'
$runtime = '/etc/openclash/精准稳定-v1-r4-ha.yaml'
$pool = '🤖 ChatGPT 专用节点池'
$apiBase = "http://${router}:9090"
$secret = (ssh -o BatchMode=yes "root@$router" "grep '^secret:' '$runtime' | head -n1 | cut -d: -f2-").Trim().Trim('"').Trim("'")
$headers = @{ Authorization = "Bearer $secret" }

function Get-Hash([string]$Value) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Value))).Substring(0, 12).ToLowerInvariant()
}

$poolPath = [uri]::EscapeDataString($pool)
$group = Invoke-RestMethod -Uri "$apiBase/proxies/$poolPath" -Headers $headers
$candidates = @($group.all | Where-Object { $_ -ne '🧠 人工智能' })
$probeUrl = [uri]::EscapeDataString('https://chatgpt.com/api/auth/session')
$results = foreach ($candidate in $candidates) {
    $path = [uri]::EscapeDataString($candidate)
    try {
        $answer = Invoke-RestMethod -Uri "$apiBase/proxies/$path/delay?url=$probeUrl&timeout=8000" -Headers $headers -TimeoutSec 12
        [pscustomobject]@{ hash = Get-Hash $candidate; ok = $true; delay = [int]$answer.delay }
    }
    catch {
        [pscustomobject]@{ hash = Get-Hash $candidate; ok = $false; delay = 0 }
    }
}

"candidate_count=$($results.Count) success_count=$(@($results | Where-Object ok).Count) failure_count=$(@($results | Where-Object { -not $_.ok }).Count)"
$results | Where-Object ok | Sort-Object delay | Select-Object -First 5 | ForEach-Object { "working_hash=$($_.hash) delay_ms=$($_.delay)" }
