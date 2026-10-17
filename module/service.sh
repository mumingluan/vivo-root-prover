#!/system/bin/sh
MODDIR=${0%/*}
# The helper validates its root-owned state directory and owns a flock.
# Its bounded guard-status.txt is displayed by Action; no shell redirection
# opens a privileged persistent log before those checks.
"$MODDIR/bin/prover" watch "$MODDIR" >/dev/null 2>&1 &
