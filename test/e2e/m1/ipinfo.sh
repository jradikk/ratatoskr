#!/bin/sh
# Public script streamed to client stdin. Credentials stay in Secret/runtime files.
# Do not enable tracing or print curl output/errors. Only whitelisted fields leave pod.
set +x
set -eu
umask 077
private=$(mktemp -d /tmp/m1-ipinfo.XXXXXX)
trap 'rm -rf "$private"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if [ -f /etc/ratatoskr/ipinfo/token ]; then
    token=$(cat /etc/ratatoskr/ipinfo/token)
    case "$token" in
        ''|*[!A-Za-z0-9_-]*) printf '%s\n' '{"status":"inconclusive","reason":"invalid-token-format"}'; exit 0 ;;
    esac
    printf 'url = "https://ipinfo.io/json?token=%s"\n' "$token" > "$private/curl.conf"
    unset token
else
    printf 'url = "https://ipinfo.io/json"\n' > "$private/curl.conf"
fi
attempt=0
while [ "$attempt" -lt 2 ]; do
    attempt=$((attempt + 1))
    code=$(curl --config "$private/curl.conf" --ipv4 --noproxy '*' --silent \
        --connect-timeout 5 --max-time 15 --max-filesize 65536 \
        --output "$private/body" --write-out '%{http_code}' 2>/dev/null) || code=000
    if [ "$code" = 200 ]; then
        # Do not emit raw ipinfo payload, token, provider profile or diagnostics.
        if jq -e '(.ip | type == "string") and (.country | type == "string")' "$private/body" >/dev/null 2>&1; then
            jq -c '{status:"observed",ip:.ip,country:.country}' "$private/body"
        else
            printf '%s\n' '{"status":"inconclusive","reason":"invalid-response"}'
        fi
        exit 0
    fi
    if [ "$code" = 429 ] && [ "$attempt" -eq 1 ]; then
        sleep 10
    else
        break
    fi
done
printf '%s\n' '{"status":"inconclusive","reason":"external-probe-unavailable-or-rate-limited"}'
