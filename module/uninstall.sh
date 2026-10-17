#!/system/bin/sh
MODDIR=${0%/*}
# KernelSU normally removes modules during boot. For live removal, the watcher
# sees the remove flag. Keep all protected snapshots for deliberate recovery.
"$MODDIR/bin/prover" stop "$MODDIR" >/dev/null 2>&1 &&
  "$MODDIR/bin/prover" unmask >/dev/null 2>&1
exit 0
