#!/usr/bin/env python3
"""SecureS3 Vault v1: local Argon2id + envelope encryption, no video re-encryption."""
import argparse
import base64
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import subprocess
import sys
from urllib.parse import quote, urlsplit

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MAGIC = b'ES3VLT01'
HEADER = struct.Struct('>8sIIIIII16s16s12s12sQQQ16s')
WRAPPED = 48
BODY_OFFSET = HEADER.size + WRAPPED
MAX_DATA = 4 * 1024 * 1024
MAX_FILE = BODY_OFFSET + MAX_DATA + 16
MAX_REVISION = 2**32 - 1
MAX_FILES = 10000
WRAP_AAD = b'SecureS3 Vault wrap v1\x00'
DATA_AAD = b'SecureS3 Vault data v1\x00'


class VaultError(ValueError):
    pass


def password_bytes(password, new=False):
    if not isinstance(password, str) or len(password) > 1024:
        raise VaultError('Invalid password encoding')
    try:
        raw = password.encode('utf-8', errors='strict')
    except UnicodeError:
        raise VaultError('Password must be well-formed Unicode') from None
    if not raw or len(raw) > 1024 or (new and len(password) < 12):
        raise VaultError('Use at least 12 characters for a new password; maximum 1024 UTF-8 bytes')
    return raw  # Exact UTF-8; no normalization, trimming or case folding.


def validate_kdf(memory, iterations, lanes):
    if (any(type(x) is not int for x in (memory, iterations, lanes)) or
            not 65536 <= memory <= 262144 or not 3 <= iterations <= 6 or
            not 1 <= lanes <= 4 or memory % (4 * lanes)):
        raise VaultError('Unsupported or excessive Argon2id parameters')


def derive(password, salt, memory=65536, iterations=3, lanes=1):
    validate_kdf(memory, iterations, lanes)
    if len(salt) != 16:
        raise VaultError('Invalid salt')
    return Argon2id(salt=salt, length=32, iterations=iterations, lanes=lanes,
                    memory_cost=memory).derive(password_bytes(password))


def file_key(text):
    if not isinstance(text, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', text):
        raise VaultError('Invalid file key')
    raw = base64.urlsafe_b64decode(text + '=')
    if base64.urlsafe_b64encode(raw).decode().rstrip('=') != text or len(raw) != 32:
        raise VaultError('Invalid file key')
    return raw


def validate_url(text):
    if (not isinstance(text, str) or len(text) > 8192 or '\\' in text or
            re.search(r'[\x00-\x20\x7f]', text) or not re.match(r'^https?://', text)):
        raise VaultError('Invalid object URL')
    try:
        url = urlsplit(text)
        host = url.hostname
        if (not host or not host.isascii() or url.username is not None or url.password is not None or
                url.fragment or (url.port is not None and not 1 <= url.port <= 65535) or
                (url.scheme == 'http' and host not in ('localhost', '127.0.0.1', '::1')) or
                len(quote(text, safe=":/?#[]@!$&'()*+,;=%-._~")) > 8192):
            raise ValueError()
    except (ValueError, UnicodeError):
        raise VaultError('Use an HTTPS URL with an ASCII/Punycode host; localhost HTTP is for tests') from None
    return text


def validate_data(data, revision):
    if (not isinstance(data, dict) or set(data) != {'version', 'revision', 'files'} or
            type(data['version']) is not int or data['version'] != 1 or
            type(data['revision']) is not int or data['revision'] != revision or
            not isinstance(data['files'], list) or len(data['files']) > MAX_FILES):
        raise VaultError('Invalid Vault directory')
    ids, urls, keys = set(), set(), set()
    for item in data['files']:
        if not isinstance(item, dict) or set(item) != {'id', 'name', 'url', 'key'}:
            raise VaultError('Invalid Vault record')
        if not isinstance(item['id'], str) or not re.fullmatch(r'[a-f0-9]{32}', item['id']):
            raise VaultError('Invalid record ID')
        name = item['name']
        if (not isinstance(name, str) or not name or len(name.encode('utf-8')) > 1024 or
                re.search(r'[\x00-\x1f\x7f]', name)):
            raise VaultError('Invalid record name')
        validate_url(item['url'])
        file_key(item['key'])
        if item['id'] in ids or item['url'] in urls or item['key'] in keys:
            raise VaultError('Duplicate record ID, URL or file key')
        ids.add(item['id']); urls.add(item['url']); keys.add(item['key'])
    return data


def encode_data(data):
    # Fixed field order and UTF-8, identical to JSON.stringify in the browser.
    ordered = {'version': 1, 'revision': data['revision'], 'files': [
        {k: item[k] for k in ('id', 'name', 'url', 'key')} for item in data['files']]}
    raw = json.dumps(ordered, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(raw) > MAX_DATA:
        raise VaultError('Vault directory exceeds 4 MiB')
    return raw


@dataclass(frozen=True)
class Metadata:
    memory: int
    iterations: int
    lanes: int
    vault_id: bytes
    salt: bytes
    wrap_nonce: bytes
    data_nonce: bytes
    revision: int
    data_revision: int
    length: int

    def pack(self):
        return HEADER.pack(MAGIC, 1, 1, 19, self.memory, self.iterations, self.lanes,
                           self.vault_id, self.salt, self.wrap_nonce, self.data_nonce,
                           self.revision, self.data_revision, self.length, bytes(16))

    def aad(self):
        return DATA_AAD + self.vault_id + struct.pack('>QQ', self.data_revision, self.length)


def parse(raw):
    if not BODY_OFFSET + 16 <= len(raw) <= MAX_FILE:
        raise VaultError('Invalid Vault length')
    magic, version, kdf, argon, m, t, p, vid, salt, wn, dn, rev, dr, length, reserved = HEADER.unpack(raw[:128])
    if (magic != MAGIC or version != 1 or kdf != 1 or argon != 19 or reserved != bytes(16) or
            not 1 <= dr <= rev <= MAX_REVISION or not 16 <= length <= MAX_DATA + 16 or
            BODY_OFFSET + length != len(raw)):
        raise VaultError('Unsupported or malformed Vault header')
    validate_kdf(m, t, p)
    return Metadata(m, t, p, vid, salt, wn, dn, rev, dr, length)


@dataclass
class Unlocked:
    meta: Metadata
    data: dict
    key: bytes
    kek: bytes
    body: bytes


def open_with_kek(raw, kek):
    meta = parse(raw)
    try:
        key = AESGCM(kek).decrypt(meta.wrap_nonce, raw[128:BODY_OFFSET], WRAP_AAD + raw[:128])
        if len(key) != 32:
            raise VaultError('Invalid Vault key')
        plain = AESGCM(key).decrypt(meta.data_nonce, raw[BODY_OFFSET:], meta.aad())
        text = plain.decode('utf-8', errors='strict')
        data = json.loads(text)
        validate_data(data, meta.data_revision)
        if encode_data(data) != plain:
            raise VaultError('Non-canonical Vault directory')
    except (InvalidTag, UnicodeError, json.JSONDecodeError, RecursionError):
        raise VaultError('Incorrect master password or damaged Vault') from None
    return Unlocked(meta, data, key, kek, raw[BODY_OFFSET:])


def unlock(raw, password):
    m = parse(raw)  # Bound hostile KDF parameters before invoking Argon2id.
    return open_with_kek(raw, derive(password, m.salt, m.memory, m.iterations, m.lanes))


def nonce(previous=b''):
    for _ in range(8):
        value = os.urandom(12)
        if value != previous:
            return value
    raise VaultError('Random nonce generation failed')


def seal(meta, data, key, kek, body=None):
    validate_data(data, meta.data_revision)
    if body is None:
        plain = encode_data(data)
        meta = replace(meta, length=len(plain) + 16)
        body = AESGCM(key).encrypt(meta.data_nonce, plain, meta.aad())
    header = meta.pack()
    wrapped = AESGCM(kek).encrypt(meta.wrap_nonce, key, WRAP_AAD + header)
    raw = header + wrapped + body
    open_with_kek(raw, kek)  # Verify a complete replacement before writing anything.
    return raw


def create(password, memory=65536, iterations=3, lanes=1):
    password_bytes(password, new=True)
    salt = os.urandom(16)
    kek = derive(password, salt, memory, iterations, lanes)
    meta = Metadata(memory, iterations, lanes, os.urandom(16), salt, nonce(), nonce(), 1, 1, 16)
    return seal(meta, {'version': 1, 'revision': 1, 'files': []}, os.urandom(32), kek)


def update(vault, files):
    rev = vault.meta.revision + 1
    if rev > MAX_REVISION:
        raise VaultError('Vault revision exhausted; create a new Vault')
    meta = replace(vault.meta, revision=rev, data_revision=rev,
                   wrap_nonce=nonce(vault.meta.wrap_nonce), data_nonce=nonce(vault.meta.data_nonce))
    return seal(meta, {'version': 1, 'revision': rev, 'files': files}, vault.key, vault.kek)


def add(vault, name, url, key, record_id=None):
    item = {'id': record_id or secrets.token_hex(16), 'name': name, 'url': url, 'key': key}
    return update(vault, [*vault.data['files'], item])


def remove(vault, record_id):
    files = [f for f in vault.data['files'] if f['id'] != record_id]
    if len(files) == len(vault.data['files']):
        raise VaultError('Record not found')
    return update(vault, files)


def change_password(vault, password, memory=65536, iterations=3, lanes=1):
    password_bytes(password, new=True)
    if vault.meta.revision == MAX_REVISION:
        raise VaultError('Vault revision exhausted')
    salt = os.urandom(16)
    for _ in range(8):
        if salt != vault.meta.salt: break
        salt = os.urandom(16)
    else: raise VaultError('Random salt generation failed')
    kek = derive(password, salt, memory, iterations, lanes)
    meta = replace(vault.meta, memory=memory, iterations=iterations, lanes=lanes,
                   revision=vault.meta.revision + 1, salt=salt, wrap_nonce=nonce(vault.meta.wrap_nonce))
    return seal(meta, vault.data, vault.key, kek, body=vault.body)


class VaultFile(AbstractContextManager):
    """Private pinned directory, cooperative single writer, fsync + atomic replace."""
    def __init__(self, path):
        path = Path(path).absolute()
        self.parent = path.parent.resolve(); self.name = path.name
        self.fd = self.lock = None

    def __enter__(self):
        self.fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            info = os.fstat(self.fd)
            if info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                raise VaultError('Use a private Vault directory (chmod 700)')
            self.lock = os.open('.' + self.name + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            info = os.fstat(self.lock)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
                raise VaultError('Unsafe Vault lock file')
            fcntl.flock(self.lock, fcntl.LOCK_EX)
            return self
        except BaseException:
            self.__exit__(None, None, None); raise

    def __exit__(self, *args):
        if self.lock is not None: os.close(self.lock); self.lock = None
        if self.fd is not None: os.close(self.fd); self.fd = None

    def read(self):
        fd = os.open(self.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        with os.fdopen(fd, 'rb') as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode) or os.fstat(f.fileno()).st_size > MAX_FILE:
                raise VaultError('Vault must be a bounded regular file')
            raw = f.read(MAX_FILE + 1)
        parse(raw)
        return raw

    def _write(self, target, raw, exclusive=False):
        tmp = '.' + self.name + '.' + secrets.token_hex(16) + '.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(raw); f.flush(); os.fsync(f.fileno())
            if exclusive:
                os.link(tmp, target, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
            else:
                os.replace(tmp, target, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try: os.unlink(tmp, dir_fd=self.fd)
            except FileNotFoundError: pass

    def commit(self, raw, previous=None):
        parse(raw)
        if previous is None:
            self._write(self.name, raw, exclusive=True)
        else:
            if self.read() != previous:
                raise VaultError('Vault changed outside this writer; refusing overwrite')
            self._write(self.name + '.bak', previous)
            self._write(self.name, raw)


def read_key(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode): raise VaultError('Key file must be a regular file')
        raw = f.read(129)
        if len(raw) > 128: raise VaultError('Key file exceeds size limit')
    try:
        key = raw.decode('ascii').strip()
        file_key(key)
        return key
    except (UnicodeError, ValueError):
        raise VaultError('Invalid key file') from None


def verify_video(path, key):
    import encrypt as video
    with open(path, 'rb') as src:
        header = src.read(48)
        magic, version, chunk, size, file_id, reserved = video.HEADER.unpack(header)
        count = max(1, (size + video.CHUNK - 1) // video.CHUNK)
        if header != video.make_header(size, file_id) or os.fstat(src.fileno()).st_size != 48 + size + count * 16:
            raise VaultError('Invalid video container')
        aes = AESGCM(file_key(key))
        for i in range(count):
            counter = struct.pack('>I', i)
            aes.decrypt(file_id[:8] + counter, src.read(min(chunk, size - i * chunk) + 16), header + counter)
    return file_id.hex()


def copy_remote(source, remote, is_vault=False):
    args = ['rclone', 'copyto', '--progress', '--retries', '1', '--low-level-retries', '1']
    if is_vault: args += ['--header-upload', 'Cache-Control: no-store']
    result = subprocess.run([*args, '--', str(source), remote], check=False)
    if result.returncode:
        raise VaultError('Upload failed; local encrypted files and current Vault are retained for retry')


def prompt(new=False):
    if not sys.stdin.isatty():
        raise VaultError('Master password requires an interactive terminal; never put it in arguments or stdin pipes')
    value = getpass.getpass('New master password: ' if new else 'Master password: ')
    if new and value != getpass.getpass('Repeat new master password: '):
        raise VaultError('Passwords do not match')
    password_bytes(value, new=new)
    return value


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    subs = p.add_subparsers(dest='command', required=True)
    init = subs.add_parser('init'); init.add_argument('--output', required=True)
    for command in ('add', 'list', 'remove', 'change-password', 'upload', 'publish'):
        sub = subs.add_parser(command); sub.add_argument('--vault', required=True)
        if command in ('add', 'publish'):
            sub.add_argument('--name', required=True); sub.add_argument('--url', required=True); sub.add_argument('--id')
            sub.add_argument('--key-file', required=command == 'add')
        if command == 'remove': sub.add_argument('--id', required=True)
        if command == 'upload': sub.add_argument('--remote', required=True)
        if command == 'publish':
            sub.add_argument('--input'); sub.add_argument('--output'); sub.add_argument('--key-out'); sub.add_argument('--cipher')
            sub.add_argument('--remote', required=True); sub.add_argument('--vault-remote', required=True)
        if command == 'change-password': sub.add_argument('--memory-kib', type=int, default=65536); sub.add_argument('--iterations', type=int, default=3)
    args = p.parse_args(argv)
    try:
        if args.command == 'init':
            raw = create(prompt(new=True))
            with VaultFile(args.output) as store: store.commit(raw)
        else:
            with VaultFile(args.vault) as store:
                original = store.read(); vault = unlock(original, prompt())
                raw = original
                if args.command == 'add':
                    raw = add(vault, args.name, args.url, read_key(args.key_file), args.id)
                elif args.command == 'remove': raw = remove(vault, args.id)
                elif args.command == 'change-password':
                    raw = change_password(vault, prompt(new=True), args.memory_kib, args.iterations)
                elif args.command == 'upload': copy_remote(args.vault, args.remote, is_vault=True)
                elif args.command == 'publish':
                    import encrypt as video
                    if args.input:
                        if not args.output or not args.key_out or args.cipher or args.key_file:
                            raise VaultError('Use --input/--output/--key-out, or --cipher/--key-file for an explicit retry')
                        video.encrypt(args.input, args.output, args.key_out)
                        cipher, key_path = args.output, args.key_out
                    elif args.cipher and args.key_file:
                        cipher, key_path = args.cipher, args.key_file
                    else: raise VaultError('Provide encrypted files or an input/output/key-out set')
                    key = read_key(key_path); verified_id = verify_video(cipher, key); record_id = args.id or verified_id
                    candidate = {'id': record_id, 'name': args.name, 'url': args.url, 'key': key}
                    existing = next((f for f in vault.data['files'] if f['url'] == args.url), None)
                    if existing != candidate:
                        if existing: raise VaultError('Object URL is already registered; use a new immutable object name')
                        raw = add(vault, args.name, args.url, key, record_id)
                    copy_remote(cipher, args.remote)
                    if raw != original: store.commit(raw, previous=original)
                    copy_remote(args.vault, args.vault_remote, is_vault=True)
                if args.command not in ('upload', 'publish') and raw != original:
                    store.commit(raw, previous=original)
                meta = parse(raw)
                if args.command == 'list':
                    print(json.dumps({'vault_id': meta.vault_id.hex(), 'revision': meta.revision,
                                      'data_revision': meta.data_revision,
                                      'files': [{k: f[k] for k in ('id', 'name')} for f in vault.data['files']]}, ensure_ascii=False, indent=2))
                    return
        meta = parse(raw)
        print(json.dumps({'vault_id': meta.vault_id.hex(), 'revision': meta.revision,
                          'sha256': hashlib.sha256(raw).hexdigest()}))
    except UnsupportedAlgorithm:
        p.exit(1, 'Argon2id is unavailable; install the pinned cryptography wheels with a supported OpenSSL build.\n')
    except (OSError, ValueError, InvalidTag, struct.error) as exc:
        p.exit(1, f'Vault operation failed: {exc}\n')


if __name__ == '__main__': main()
