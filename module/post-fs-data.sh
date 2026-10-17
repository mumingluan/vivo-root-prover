#!/system/bin/sh
MODDIR=${0%/*}
# Earliest module stage: only kernel control commands, no block-device writes.
"$MODDIR/bin/prover" gate >/dev/null 2>&1
exit 0
