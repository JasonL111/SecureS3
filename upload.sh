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
exec rclone copyto --progress -- "$1" "$2"
