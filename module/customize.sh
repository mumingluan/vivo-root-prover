#!/system/bin/sh
[ "$KSU" = true ] || abort "vivo Root Prover requires KernelSU"
[ "$ARCH" = arm64 ] || abort "Only arm64 is supported"
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/bin/prover" 0 0 0755
for script in customize.sh post-fs-data.sh service.sh boot-completed.sh action.sh uninstall.sh proverctl.sh; do
  set_perm "$MODPATH/$script" 0 0 0755
done
ui_print "vivo Root Prover 0.3.2"
ui_print "Runtime kernel, HAL, NV layout and device identity checks are required"
ui_print "Installation does not clear NV or mount history. Action displays status."
ui_print "Unknown firmware or denied operations are reported, never bypassed."
