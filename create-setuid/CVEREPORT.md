# fuse-overlayfs: FUSE_CREATE keeps S_ISUID on the upper layer

**Affected:** fuse-overlayfs `ovl_create()` / `direct_create_file()`.
**CWE:** CWE-269

`mode & ~ctx->umask` does not drop S_ISUID/S_ISGID. Root daemon + `allow_other` → setuid-root file on upper.

## Reproduce

See `poc_create_mode_setuid.sh` if present; otherwise `open(..., 04711)` on the overlay.

**Fix:** clear 047000 before `openat`.