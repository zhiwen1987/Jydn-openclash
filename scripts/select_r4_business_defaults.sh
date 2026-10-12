#!/bin/sh
# Select the four R4 service-aware pools through the local Mihomo API.

set -eu

config_path="${1:-/etc/openclash/精准稳定-v1-r4-ha.yaml}"
controller_port="$(ruby -ryaml -e 'c=YAML.unsafe_load_file(ARGV[0]); print c.fetch("external-controller").to_s.split(":").last' "$config_path")"
secret="$(ruby -ryaml -e 'c=YAML.unsafe_load_file(ARGV[0]); print c.fetch("secret", "")' "$config_path")"
api="http://127.0.0.1:$controller_port"

select_group() {
  label="$1"
  encoded_group="$2"
  pool="$3"
  body="$(printf '{"name":"%s"}' "$pool")"
  code="$(curl -sS -o /dev/null -w '%{http_code}' \
    -X PUT "$api/proxies/$encoded_group" \
    -H "Authorization: Bearer $secret" \
    -H 'Content-Type: application/json' \
    --data "$body")"
  case "$code" in
    2??) ;;
    *) echo "cannot select $label: HTTP $code" >&2; exit 1 ;;
  esac

  response="$(curl -sS "$api/proxies/$encoded_group" -H "Authorization: Bearer $secret")"
  actual="$(jsonfilter -s "$response" -e '@.now')"
  if [ "$actual" != "$pool" ]; then
    echo "selection mismatch for $label" >&2
    exit 1
  fi
  echo "$label=$pool"
}

select_group 'ChatGPT' '%F0%9F%A4%96%20%E5%AF%B9%E8%AF%9D%E5%8A%A9%E6%89%8B%EF%BC%88ChatGPT%EF%BC%89' '🤖 ChatGPT 专用节点池'
select_group 'Claude' '%F0%9F%9F%A0%20%E5%AF%B9%E8%AF%9D%E5%8A%A9%E6%89%8B%EF%BC%88Claude%EF%BC%89' '🟠 Claude 专用节点池'
select_group 'Gemini' '%F0%9F%94%B5%20%E5%AF%B9%E8%AF%9D%E5%8A%A9%E6%89%8B%EF%BC%88Gemini%EF%BC%89' '🔵 Gemini 专用节点池'
select_group 'Netflix' '%F0%9F%8E%A5%20%E6%B5%81%E5%AA%92%E4%BD%93%EF%BC%88Netflix%EF%BC%89' '🎥 Netflix 专用节点池'

unset secret
