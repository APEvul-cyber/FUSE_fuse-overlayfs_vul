# S_ISUID/S_ISGID bits not stripped from create mode in ovl_create()

In `main.c`, `ovl_create()` passes the FUSE_CREATE mode to `direct_create_file()` with only the umask stripped (`mode & ~ctx->umask`). The `S_ISUID` and `S_ISGID` bits are preserved and applied to the upper-layer file. When fuse-overlayfs runs as root, an unprivileged user can create setuid-root files on the upper layer, leading to local privilege escalation.

## Steps to Reproduce

1. Run fuse-overlayfs as root:
   ```bash
   mkdir -p /tmp/lower /tmp/upper /tmp/work /mnt/overlay
   fuse-overlayfs -o lowerdir=/tmp/lower,upperdir=/tmp/upper,workdir=/tmp/work,allow_other /mnt/overlay
   ```
2. As an unprivileged user:
   ```bash
   python3 -c "
   import os
   fd = os.open('/mnt/overlay/test', os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o4711)
   os.close(fd)
   "
   ```
3. Check the upper-layer file:
   ```bash
   stat /tmp/upper/test
   ```

## Expected Behavior

`S_ISUID` and `S_ISGID` should be stripped from the mode for non-root callers before creating the file on the upper layer. Native filesystem semantics ensure that setuid on creation only refers to the creator's own UID; when the backing file is owned by root, the daemon must not honor a non-root caller's setuid request.

## Actual Behavior

The upper-layer file is created with `mode=04711`, `uid=0`, `gid=0`. The `S_ISUID` bit is preserved on a root-owned file. On a mount without `nosuid`, executing this file grants root privileges.

## Affected Code

`main.c`, `ovl_create()` (around line 3872):

```c
fd = direct_create_file(get_upper_layer(lo), ..., flags, mode & ~ctx->umask);
```

The umask is stripped but `S_ISUID`/`S_ISGID` pass through to `safe_openat()`.

## Suggested Fix

Strip setuid/setgid bits before passing the mode to `direct_create_file()`:

```c
mode_t safe_mode = mode & ~ctx->umask;
safe_mode &= ~(S_ISUID | S_ISGID);
fd = direct_create_file(get_upper_layer(lo), ..., flags, safe_mode);
```

---

**Full PoC and scripts**: [GitHub Repository](https://github.com/APEvul-cyber/FUSE_fuse-overlayfs_vul/tree/main/CREATE_mode_response)
