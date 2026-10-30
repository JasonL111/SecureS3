#!/usr/bin/env python3
"""ES3VID01: bounded-memory, independently authenticated AES-256-GCM chunks."""
import argparse
import base64
import os
from pathlib import Path
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b'ES3VID01'
CHUNK = 4 * 1024 * 1024
HEADER = struct.Struct('>8sIIQ16s8s')
MAX_SAFE = 2**53 - 1


def make_header(size, file_id):
    count = max(1, (size + CHUNK - 1) // CHUNK)
    if size < 0 or count > 2**32 or HEADER.size + size + count * 16 > MAX_SAFE:
        raise ValueError('File exceeds protocol integer limits')
    return HEADER.pack(MAGIC, 1, CHUNK, size, file_id, bytes(8))


def encrypt(source, output, key_out):
    paths = [Path(p).resolve() for p in (source, output, key_out)]
    if len(set(paths)) != 3:
        raise ValueError('Input, ciphertext and key must have distinct paths')
    # Exclusive creation prevents overwriting existing files (including symlinks).
    created = []
    try:
        with open(source, 'rb') as src:
            size = os.fstat(src.fileno()).st_size
            file_id, key = os.urandom(16), AESGCM.generate_key(bit_length=256)
            header = make_header(size, file_id)
            cipher = AESGCM(key)
            with open(output, 'xb') as dst:
                created.append(output)
                dst.write(header)
                remaining = size
                for index in range(max(1, (size + CHUNK - 1) // CHUNK)):
                    block = src.read(min(CHUNK, remaining))
                    if len(block) != min(CHUNK, remaining):
                        raise OSError('Input changed during encryption')
                    counter = struct.pack('>I', index)
                    dst.write(cipher.encrypt(file_id[:8] + counter, block, header + counter))
                    remaining -= len(block)
                if src.read(1) or os.fstat(src.fileno()).st_size != size:
                    raise OSError('Input changed during encryption')
            fd = os.open(key_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(key_out)
            with os.fdopen(fd, 'w', encoding='ascii') as dst:
                dst.write(base64.urlsafe_b64encode(key).rstrip(b'=').decode() + '\n')
    except BaseException:
        for path in reversed(created):
            Path(path).unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input')
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('--key-out', required=True)
    args = parser.parse_args()
    try:
        encrypt(args.input, args.output, args.key_out)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'Encryption failed: {exc}\n')
    print('Encrypted. Keep the .key file private; upload only the ciphertext.')


if __name__ == '__main__':
    main()
