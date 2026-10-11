#!/usr/bin/env bash
# probe-host.sh — per-host baseline capture (404 control + auth-relevant headers)
# Usage: probe-host.sh <host> [host...]
while [ -n "$1" ]; do
  H=$1; shift
  echo "=== $H ==="
  for P in /zzz-nope-12345 /; do
    printf '  %-16s ' "$P"
    curl -sk -m 12 -D "$TMPDIR/$H.hdr" -o "$TMPDIR/$H.body" \
      -w '%{http_code} %{size_download} ' "https://$H$P" 2>/dev/null
    sha256sum "$TMPDIR/$H.body" | cut -c1-16
  done
  echo '  headers:'
  grep -aiE '^(server|x-powered-by|content-security-policy|x-frame-options|'\
'access-control-allow-origin|access-control-allow-credentials|'\
'strict-transport-security|via|x-amz-cf-id|x-generator):' \
    "$TMPDIR/$H.hdr" | tr -d '\r' | sed 's/^/    /'
done
