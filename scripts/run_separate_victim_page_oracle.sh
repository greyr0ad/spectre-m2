#!/bin/bash
# Fresh-process-per-round separated-victim page oracle.
set -uo pipefail

cd "$(dirname "$0")/.."

BIN="./build/separate_victim_page_oracle"
ROUNDS="${ROUNDS:-20}"
CANDS=16
SLEEP="${SLEEP:-3}"

if [ ! -x "$BIN" ]; then
    echo "ERROR: $BIN not built. Run: make separate-victim-page-oracle" >&2
    exit 2
fi
case "$ROUNDS" in
    ''|*[!0-9]*)
        echo "ERROR: ROUNDS must be a positive integer" >&2
        exit 2
        ;;
esac
if [ "$ROUNDS" -lt 1 ]; then
    echo "ERROR: ROUNDS must be a positive integer" >&2
    exit 2
fi

echo "SEPARATED-VICTIM PAGE ORACLE"
echo "victim_page_oracle.c is compiled separately. ${CANDS} candidates. ${ROUNDS} rounds."
echo ""

correct=0
for r in $(seq 1 "$ROUNDS"); do
    secret=$(( (RANDOM + r * 7) % CANDS ))
    result=""
    for retry in 1 2 3; do
        result=$("$BIN" --round="$r" --secret="$secret" 2>/dev/null)
        if [ -n "$result" ]; then break; fi
        sleep 1
    done
    if [ -z "$result" ]; then
        echo "  round $r: ERROR after 3 retries"
        sleep "$SLEEP"
        continue
    fi
    echo "  $result"
    if echo "$result" | grep -q CORRECT; then
        correct=$((correct + 1))
    fi
    sleep "$SLEEP"
done

awk -v correct="$correct" -v rounds="$ROUNDS" -v cands="$CANDS" 'BEGIN {
    chance = 100.0 / cands;
    acc = 100.0 * correct / rounds;
    printf "\naccuracy: %d/%d (%.1f%%)  chance=%.1f%%  lift=%.1fx\n",
           correct, rounds, acc, chance, acc / chance;
}'
