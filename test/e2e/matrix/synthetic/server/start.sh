#!/bin/sh
# The server and marker listener share this Pod's tunnel namespace.
set -eu
umask 077
/usr/sbin/openvpn --config /etc/synthetic/server.conf --verb 0 >/dev/null 2>&1 &
vpn=$!
trap 'kill "$vpn" 2>/dev/null || :; wait "$vpn" 2>/dev/null || :' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
# Bind only to the tunnel endpoint, never a cluster/public-facing socket.
i=0
until ip -4 addr show dev tun0 2>/dev/null | grep -q '10\.88\.0\.1/'; do
    kill -0 "$vpn" 2>/dev/null || exit 1
    i=$((i + 1))
    [ "$i" -le 30 ] || exit 1
    sleep 1
done
python3 /usr/local/bin/serve.py &
listener=$!
trap 'kill "$listener" "$vpn" 2>/dev/null || :; wait "$listener" "$vpn" 2>/dev/null || :' EXIT
wait "$listener"
