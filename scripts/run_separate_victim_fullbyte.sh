#!/bin/bash
# Fresh-process-per-nibble separated-victim full-byte recovery.
set -uo pipefail

cd "$(dirname "$0")/.."

BIN="./build/separate_victim_fullbyte"
KEY="s3cr3t-k3y!"
KEYLEN=${#KEY}
BYTES="${BYTES:-$KEYLEN}"
SLEEP="${SLEEP:-3}"

if [ ! -x "$BIN" ]; then
    echo "ERROR: $BIN not built. Run: make separate-victim-fullbyte" >&2
    exit 2
fi
case "$BYTES" in
    ''|*[!0-9]*)
        echo "ERROR: BYTES must be an integer between 1 and $KEYLEN" >&2
        exit 2
        ;;
esac
if [ "$BYTES" -lt 1 ] || [ "$BYTES" -gt "$KEYLEN" ]; then
    echo "ERROR: BYTES must be an integer between 1 and $KEYLEN" >&2
    exit 2
fi

echo "SEPARATED-VICTIM FULL-BYTE RECOVERY"
echo "victim_fullbyte.c is compiled separately. fresh process per nibble."
echo "private key: \"$KEY\" ($KEYLEN bytes); recovering $BYTES byte(s)"
echo ""

correct=0
hexbytes=""

for i in $(seq 0 $((BYTES - 1))); do
    expected_char="${KEY:$i:1}"
    expected_hex=$(printf '%02x' "'$expected_char")

    hi="x"
    for retry in 1 2 3 4 5; do
        r=$("$BIN" --nibble="$i:hi" 2>/dev/null) || true
        h=$(echo "$r" | grep -o 'got=[0-9a-f]*' 2>/dev/null | head -1 | cut -d= -f2) || true
        if [ -n "$h" ]; then hi="$h"; break; fi
        sleep 1
    done
    sleep "$SLEEP"

    lo="x"
    for retry in 1 2 3 4 5; do
        r=$("$BIN" --nibble="$i:lo" 2>/dev/null) || true
        l=$(echo "$r" | grep -o 'got=[0-9a-f]*' 2>/dev/null | head -1 | cut -d= -f2) || true
        if [ -n "$l" ]; then lo="$l"; break; fi
        sleep 1
    done
    sleep "$SLEEP"

    byte_hex="${hi}${lo}"
    hexbytes="$hexbytes $byte_hex"

    ok="MISS"
    if [ "$byte_hex" = "$expected_hex" ]; then
        ok="OK"
        correct=$((correct + 1))
    fi
    echo "  byte $((i+1))/$BYTES: expected=0x$expected_hex '$expected_char'  got=0x$byte_hex  $ok"
done

echo ""
echo "private key: $KEY"
echo -n "recovered:   "
for hx in $hexbytes; do
    if [[ "$hx" == *x* ]]; then
        echo -n "?"
    else
        printf "\\x$hx"
    fi
done
echo ""
echo "accuracy: $correct/$BYTES bytes"
