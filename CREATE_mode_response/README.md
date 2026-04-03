# CREATE:mode — S_ISUID/S_ISGID Bit Not Filtered in fuse-overlayfs

## Vulnerability

FUSE daemon passes user-supplied `mode` (including `S_ISUID`/`S_ISGID` bits) directly to the backing store without sanitization. When the daemon runs as root, this allows non-privileged users to create setuid-root executables, leading to local privilege escalation.

## Files

| File | Description |
|------|-------------|
| `CREATE_mode_response.txt` | Original PoC analysis |
| `poc_create_mode_setuid.sh` | PoC test script |
| `poc_output.txt` | PoC execution output |
| `report_cve.md` | CVE report (GHSA style) |
| `report_issue.md` | GitHub Issue report |

## Environment Requirements

- Docker with `--privileged` or `--cap-add SYS_ADMIN --device /dev/fuse`
- Ubuntu 24.04 base image
- libfuse3 compiled from source (for `passthrough_ll` example binary)
- `gcc` for compiling the helper C program

## How to Run

### 1. Build the Docker Environment

```bash
docker build -t fuse-poc-env .
docker run --rm --privileged --device /dev/fuse \
  --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
  -it fuse-poc-env bash
```

### 2. Inside the Container

```bash
# Compile libfuse if not already done
cd /opt/libfuse && mkdir -p build && cd build
meson setup .. && ninja

# Run the PoC
bash poc_create_mode_setuid.sh
```

### 3. Expected Output

The script will:
1. Start `passthrough_ll` as root with a backing store directory
2. Create a file with mode `04711` (S_ISUID set) via the FUSE mount
3. Check the backing store file permissions

**Vulnerable result**: Backing store file has `S_ISUID` bit set and is owned by `root` (UID=0).

```
Backing store file: mode=4711 uid=0 gid=0
S_ISUID bit: YES
S_ISGID bit: YES (also not filtered)
RESULT: VULNERABLE
```
