#!/usr/bin/env python3
"""ES3VID01: bounded-memory, independently authenticated AES-256-GCM chunks."""
import argparse
import base64
from contextlib import ExitStack
import os
from pathlib import Path
import struct
import stat

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b'ES3VID01'
CHUNK = 4 * 1024 * 1024
HEADER = struct.Struct('>8sIIQ16s8s')
MAX_SAFE = 2**53 - 1


def make_header(size, file_id):
    if type(size) is not int or len(file_id) != 16:
        raise ValueError('Invalid size or file identifier')
    count = max(1, (size + CHUNK - 1) // CHUNK)
    if size < 0 or count > 2**32 or HEADER.size + size + count * 16 > MAX_SAFE:
        raise ValueError('File exceeds protocol integer limits')
    return HEADER.pack(MAGIC, 1, CHUNK, size, file_id, bytes(8))


def encrypt(source, output, key_out):
    paths = [Path(p).resolve() for p in (source, output, key_out)]
    if len(set(paths)) != 3:
        raise ValueError('Input, ciphertext and key must have distinct paths')
    # Pin directories so renaming a parent cannot redirect writes or cleanup.
    with ExitStack() as stack:
        parents = []
        for path in paths[1:]:
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            stack.callback(os.close, parent)
            info = os.fstat(parent)
            if info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                raise ValueError('Use a private output directory (not group/world writable)')
            parents.append((parent, path.name))
        created = []

        def create(index):
            parent, name = parents[index]
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
            info = os.fstat(fd)
            created.append((parent, name, info.st_dev, info.st_ino))
            return os.fdopen(fd, 'wb')

        def stamp(info):
            return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns

        try:
            fd = os.open(paths[0], os.O_RDONLY | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as src:
                before = os.fstat(src.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError('Input must be a regular, stable file')
                size = before.st_size
                file_id, key = os.urandom(16), AESGCM.generate_key(bit_length=256)
                header = make_header(size, file_id)
                cipher = AESGCM(key)
                with create(0) as dst:
                    dst.write(header)
                    remaining = size
                    for index in range(max(1, (size + CHUNK - 1) // CHUNK)):
                        block = src.read(min(CHUNK, remaining))
                        if len(block) != min(CHUNK, remaining):
                            raise OSError('Input changed during encryption')
                        counter = struct.pack('>I', index)
                        dst.write(cipher.encrypt(file_id[:8] + counter, block, header + counter))
                        remaining -= len(block)
                    if src.read(1) or stamp(os.fstat(src.fileno())) != stamp(before):
                        raise OSError('Input changed during encryption')
                    dst.flush()
                    os.fsync(dst.fileno())
                with create(1) as dst:
                    os.fchmod(dst.fileno(), 0o600)
                    dst.write(base64.urlsafe_b64encode(key).rstrip(b'=') + b'\n')
                    dst.flush()
                    os.fsync(dst.fileno())
        except BaseException:
            for parent, name, device, inode in reversed(created):
                try:
                    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (device, inode):
                        os.unlink(name, dir_fd=parent)
                except FileNotFoundError:
                    pass
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
