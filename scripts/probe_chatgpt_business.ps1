$ErrorActionPreference = 'Stop'

$router = '10.88.0.254'
$runtime = '/etc/openclash/精准稳定-v1-r4-ha.yaml'
$business = '🤖 对话助手（ChatGPT）'
$pool = '🤖 ChatGPT 专用节点池'
$apiBase = "http://${router}:9090"

$secret = (ssh -o BatchMode=yes "root@$router" "grep '^secret:' '$runtime' | head -n1 | cut -d: -f2-").Trim().Trim('"').Trim("'")
$proxyAuth = (ssh -o BatchMode=yes "root@$router" "sed -n '/^authentication:/,/^[^ -]/p' '$runtime' | sed -n 's/^[[:space:]]*-[[:space:]]*//p' | head -n1").Trim()
$proxyUser, $proxyPassword = $proxyAuth.Split(':', 2)
$proxyCredential = [pscredential]::new($proxyUser, (ConvertTo-SecureString $proxyPassword -AsPlainText -Force))
$headers = @{ Authorization = "Bearer $secret" }

$businessPath = [uri]::EscapeDataString($business)
$poolPath = [uri]::EscapeDataString($pool)
$current = (Invoke-RestMethod -Uri "$apiBase/proxies/$businessPath" -Headers $headers).now

function Get-HttpResult([string]$Url) {
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -Proxy "http://${router}:7890" -ProxyCredential $proxyCredential -TimeoutSec 12 -MaximumRedirection 0 -UserAgent 'Mozilla/5.0 OpenClash-R4-acceptance'
        return "http=$([int]$response.StatusCode)"
    }
    catch {
        if ($_.Exception.Response) {
            return "http=$([int]$_.Exception.Response.StatusCode)"
        }
        return "error=$($_.Exception.GetType().Name)"
    }
}

try {
    Invoke-RestMethod -Method Put -Uri "$apiBase/proxies/$businessPath" -Headers $headers -ContentType 'application/json' -Body (@{ name = $pool } | ConvertTo-Json -Compress) | Out-Null
    $selected = (Invoke-RestMethod -Uri "$apiBase/proxies/$poolPath" -Headers $headers).now
    $selectedHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($selected))).Substring(0, 12).ToLowerInvariant()
    "pool_member_hash=$selectedHash"
    ([ordered]@{
        chatgpt_root = 'https://chatgpt.com/'
        chatgpt_session = 'https://chatgpt.com/api/auth/session'
        openai_auth = 'https://auth.openai.com/'
        openai_api = 'https://api.openai.com/v1/models'
    }).GetEnumerator() | ForEach-Object { "$($_.Key) $(Get-HttpResult $_.Value)" }
}
finally {
    Invoke-RestMethod -Method Put -Uri "$apiBase/proxies/$businessPath" -Headers $headers -ContentType 'application/json' -Body (@{ name = $current } | ConvertTo-Json -Compress) | Out-Null
    $currentHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($current))).Substring(0, 12).ToLowerInvariant()
    "restored=true original_hash=$currentHash"
}
