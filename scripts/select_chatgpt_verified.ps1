$ErrorActionPreference = 'Stop'

$router = '10.88.0.254'
$runtime = '/etc/openclash/精准稳定-v1-r4-ha.yaml'
$business = '🤖 对话助手（ChatGPT）'
$pool = '🤖 ChatGPT 专用节点池'
$fallback = '🧠 人工智能'
$apiBase = "http://${router}:9090"
$secret = (ssh -o BatchMode=yes "root@$router" "grep '^secret:' '$runtime' | head -n1 | cut -d: -f2-").Trim().Trim('"').Trim("'")
$headers = @{ Authorization = "Bearer $secret" }

function Get-Hash([string]$Value) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Value))).Substring(0, 12).ToLowerInvariant()
}

function Resolve-Leaf([string]$Name) {
    $current = $Name
    for ($depth = 0; $depth -lt 12; $depth++) {
        $path = [uri]::EscapeDataString($current)
        try {
            $proxy = Invoke-RestMethod -Uri "$apiBase/proxies/$path" -Headers $headers
        }
        catch {
            "resolution_stopped_depth=$depth hash=$(Get-Hash $current)"
            return $current
        }
        if (-not $proxy.now -or $proxy.now -eq $current) { return $current }
        $current = $proxy.now
    }
    throw 'Proxy-group resolution exceeded the safe depth limit'
}

$poolPath = [uri]::EscapeDataString($pool)
$businessPath = [uri]::EscapeDataString($business)
$group = Invoke-RestMethod -Uri "$apiBase/proxies/$poolPath" -Headers $headers
if ($group.type -ne 'Selector') { throw "ChatGPT pool is not controller-selectable: $($group.type)" }

$probeUrl = [uri]::EscapeDataString('https://chatgpt.com/api/auth/session')
$working = foreach ($candidate in @($group.all | Where-Object { $_ -ne $fallback })) {
    $path = [uri]::EscapeDataString($candidate)
    try {
        $answer = Invoke-RestMethod -Uri "$apiBase/proxies/$path/delay?url=$probeUrl&timeout=8000" -Headers $headers -TimeoutSec 12
        [pscustomobject]@{ name = $candidate; delay = [int]$answer.delay }
    }
    catch { }
}

$best = $working | Sort-Object delay | Select-Object -First 1
if (-not $best) {
    $fallbackLeaf = Resolve-Leaf $fallback
    $fallbackTarget = if (@($group.all) -contains $fallbackLeaf) { $fallbackLeaf } else { $fallback }
    Invoke-RestMethod -Method Put -Uri "$apiBase/proxies/$poolPath" -Headers $headers -ContentType 'application/json' -Body (@{ name = $fallbackTarget } | ConvertTo-Json -Compress) | Out-Null
    Invoke-RestMethod -Method Put -Uri "$apiBase/proxies/$businessPath" -Headers $headers -ContentType 'application/json' -Body (@{ name = $pool } | ConvertTo-Json -Compress) | Out-Null
    "working_count=0 fallback_leaf_selected=true selected_hash=$(Get-Hash $fallbackTarget) business_selected=true"
    return
}

Invoke-RestMethod -Method Put -Uri "$apiBase/proxies/$poolPath" -Headers $headers -ContentType 'application/json' -Body (@{ name = $best.name } | ConvertTo-Json -Compress) | Out-Null
Invoke-RestMethod -Method Put -Uri "$apiBase/proxies/$businessPath" -Headers $headers -ContentType 'application/json' -Body (@{ name = $pool } | ConvertTo-Json -Compress) | Out-Null
"working_count=$(@($working).Count) selected_hash=$(Get-Hash $best.name) delay_ms=$($best.delay) business_selected=true"
