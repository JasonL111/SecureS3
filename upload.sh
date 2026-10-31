#!/bin/sh
set -eu
if [ "$#" -ne 2 ]; then
    echo 'Usage: sh upload.sh ciphertext.enc remote:bucket/path.enc' >&2
    exit 2
fi
case "$1" in
    *.enc) ;;
    *) echo 'Only .enc ciphertext files may be uploaded.' >&2; exit 2 ;;
esac
[ -f "$1" ] || { echo 'Ciphertext file not found.' >&2; exit 2; }
# Reject obvious misnamed keys/plaintext; this validates the container, not AEAD.
python3 - "$1" <<'PY_CHECK'
import os, stat, struct, sys
try:
    with open(sys.argv[1], 'rb') as src:
        magic, version, chunk, size, file_id, reserved = struct.unpack('>8sIIQ16s8s', src.read(48))
        count = max(1, (size + 4194303) // 4194304)
        total = 48 + size + count * 16
        valid = (magic == b'ES3VID01' and version == 1 and chunk == 4194304 and reserved == bytes(8)
                 and count <= 2**32 and total <= 2**53-1 and stat.S_ISREG(os.fstat(src.fileno()).st_mode)
                 and os.fstat(src.fileno()).st_size == total)
        if not valid: raise ValueError()
except (OSError, ValueError, struct.error):
    sys.exit('Refusing upload: not a valid SecureS3 ciphertext container.')
PY_CHECK
exec rclone copyto --progress -- "$1" "$2"
