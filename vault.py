#!/usr/bin/env python3
"""SecureS3 Vault v1: local Argon2id + envelope encryption, no video re-encryption."""
import argparse
import base64
from contextlib import AbstractContextManager, nullcontext
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
import sys
from urllib.parse import quote, urlsplit

try:
    from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ModuleNotFoundError:
    if __name__ == '__main__': sys.exit('缺少 Python 加密组件。请先按 README 安装 requirements.lock 中的依赖。')
    raise

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
MAX_ACCESS_TIME = 253402300799


def source_id(value):
    if (not isinstance(value, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,31}', value) or
            value in ('constructor', 'prototype')):
        raise VaultError('Source ID must start with a letter and contain at most 32 letters, digits, _ or -')
    return value


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
            type(data['version']) is not int or data['version'] not in (1, 2, 3) or
            type(data['revision']) is not int or data['revision'] != revision or
            not isinstance(data['files'], list) or len(data['files']) > MAX_FILES):
        raise VaultError('Invalid Vault directory')
    ids, urls, keys = set(), set(), set()
    for item in data['files']:
        opaque = isinstance(item, dict) and 'objectKey' in item
        location = 'objectKey' if opaque else 'url'
        has_access = isinstance(item, dict) and 'access' in item
        fields = {'id', 'name', location, 'key'} | ({'access'} if has_access else set())
        if (not isinstance(item, dict) or set(item) != fields or (opaque and data['version'] < 2) or
                (has_access and (not opaque or data['version'] != 3))):
            raise VaultError('Invalid Vault record')
        if not isinstance(item['id'], str) or not re.fullmatch(r'[a-f0-9]{32}', item['id']):
            raise VaultError('Invalid record ID')
        name = item['name']
        if (not isinstance(name, str) or not name or len(name.encode('utf-8')) > 1024 or
                re.search(r'[\x00-\x1f\x7f]', name)):
            raise VaultError('Invalid record name')
        if opaque:
            relative_name(name)
            if item['objectKey'] != object_key(item['id']):
                raise VaultError('Object key must match the container File ID')
        else:
            validate_url(item['url'])
        file_key(item['key'])
        if has_access: validate_access(item['access'], item['objectKey'])
        address = (location, item[location])
        if item['id'] in ids or address in urls or item['key'] in keys:
            raise VaultError('Duplicate record ID, URL or file key')
        ids.add(item['id']); urls.add(address); keys.add(item['key'])
    return data


def validate_access(access, object_key):
    if not isinstance(access, dict) or not 1 <= len(access) <= 32:
        raise VaultError('Invalid source access directory')
    for source, grant in access.items():
        source_id(source)
        if (not isinstance(grant, dict) or set(grant) != {'type', 'url', 'expiresAt'} or
                grant['type'] != 'presigned' or type(grant['expiresAt']) is not int or
                not 1 <= grant['expiresAt'] <= MAX_ACCESS_TIME):
            raise VaultError('Invalid temporary access metadata')
        validate_url(grant['url'])
        if not grant['url'].isascii(): raise VaultError('Temporary URLs must use ASCII URL encoding')
        # Loopback HTTP remains available only for local protocol tests. CLI signing requires HTTPS.
        parsed = urlsplit(grant['url'])
        if not parsed.path.endswith('/' + object_key) or not parsed.query or '#' in grant['url']:
            raise VaultError('Temporary access does not target this object')


def ordered_record(item):
    ordered = {k: item[k] for k in ('id', 'name', 'objectKey' if 'objectKey' in item else 'url', 'key')}
    if 'access' in item:
        ordered['access'] = {s: {k: item['access'][s][k] for k in ('type', 'url', 'expiresAt')}
                             for s in sorted(item['access'])}
    return ordered


def encode_data(data):
    # Fixed field order and UTF-8, identical to JSON.stringify in the browser.
    ordered = {'version': data['version'], 'revision': data['revision'], 'files': [
        ordered_record(item) for item in data['files']]}
    raw = json.dumps(ordered, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(raw) > MAX_DATA:
        raise VaultError('Vault directory exceeds 4 MiB')
    return raw


def object_key(file_id):
    if not isinstance(file_id, str) or not re.fullmatch(r'[a-f0-9]{32}', file_id):
        raise VaultError('Invalid File ID')
    return f'objects/{file_id}.enc'


def relative_name(name):
    if (not isinstance(name, str) or not name or len(name.encode('utf-8')) > 1024 or
            re.search(r'[\x00-\x1f\x7f\\]', name) or
            any(part in ('', '.', '..') for part in name.split('/')) or
            re.match(r'^[a-zA-Z]:', name)):
        raise VaultError('Use a safe relative video path')
    return name


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
    version = max(vault.data['version'], 3 if any('access' in f for f in files) else
                  2 if any('objectKey' in f for f in files) else 1)
    return seal(meta, {'version': version, 'revision': rev, 'files': files}, vault.key, vault.kek)


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


def verify_video(path, key, details=False):
    import encrypt as video
    with nullcontext(path) if hasattr(path, 'read') else open(path, 'rb') as src:
        before = os.fstat(src.fileno())
        if not stat.S_ISREG(before.st_mode): raise VaultError('Video must be a regular file')
        header = src.read(48)
        if len(header) != 48: raise VaultError('Truncated video header')
        magic, version, chunk, size, file_id, reserved = video.HEADER.unpack(header)
        count = max(1, (size + video.CHUNK - 1) // video.CHUNK)
        if header != video.make_header(size, file_id) or os.fstat(src.fileno()).st_size != 48 + size + count * 16:
            raise VaultError('Invalid video container')
        aes = AESGCM(file_key(key))
        plain_hash, cipher_hash = hashlib.sha256(), hashlib.sha256(header)
        for i in range(count):
            counter = struct.pack('>I', i)
            block = src.read(min(chunk, size - i * chunk) + 16)
            plain_hash.update(aes.decrypt(file_id[:8] + counter, block, header + counter))
            cipher_hash.update(block)
        after = os.fstat(src.fileno())
        stamp = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if src.read(1) or stamp(before) != stamp(after): raise VaultError('Ciphertext changed during verification')
    if details:
        return {'id': file_id.hex(), 'size': size, 'plain_sha256': plain_hash.hexdigest(),
                'cipher_sha256': cipher_hash.hexdigest(), 'cipher_size': before.st_size}
    return file_id.hex()


def copy_remote(source, remote, is_vault=False):
    from presign import run_rclone
    args = ['copyto']
    if is_vault: args += ['--header-upload', 'Cache-Control: no-store']
    # Vaults are at most ~4 MiB; retain a finite but much larger budget for legacy video publish.
    try: run_rclone([*args, '--', str(source), remote], timeout=120 if is_vault else 86400)
    except (ValueError, OSError):
        raise VaultError('Upload failed; local encrypted files and current Vault are retained. Retry vault.py upload without signing again') from None


def prompt(new=False):
    if not sys.stdin.isatty():
        raise VaultError('Master password requires an interactive terminal; never put it in arguments or stdin pipes')
    value = getpass.getpass('New master password: ' if new else 'Master password: ')
    if new and value != getpass.getpass('Repeat new master password: '):
        raise VaultError('Passwords do not match')
    password_bytes(value, new=new)
    return value


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if not arguments:
        from interactive import run
        return run()
    p = argparse.ArgumentParser(description=__doc__)
    subs = p.add_subparsers(dest='command', required=True)
    init = subs.add_parser('init'); init.add_argument('--output', required=True)
    batch = subs.add_parser('batch-encrypt')
    batch.add_argument('--input-dir', required=True); batch.add_argument('--output-dir', required=True)
    batch.add_argument('--private-dir', required=True); batch.add_argument('--recursive', action='store_true')
    batch.add_argument('--dry-run', action='store_true')
    for command in ('add', 'list', 'remove', 'change-password', 'upload', 'publish', 'batch-add', 'migrate', 'presign'):
        sub = subs.add_parser(command); sub.add_argument('--vault', required=True)
        if command in ('add', 'publish'):
            sub.add_argument('--name', required=True); sub.add_argument('--url', required=True); sub.add_argument('--id')
            sub.add_argument('--key-file', required=command == 'add')
        if command == 'remove': sub.add_argument('--id', required=True)
        if command == 'batch-add': sub.add_argument('--manifest', required=True)
        if command == 'migrate':
            sub.add_argument('--id', required=True); sub.add_argument('--cipher', required=True)
            sub.add_argument('--output-dir', required=True); sub.add_argument('--name')
        if command == 'upload': sub.add_argument('--remote', required=True)
        if command == 'presign':
            sub.add_argument('--source', required=True); sub.add_argument('--remote', required=True)
            sub.add_argument('--expires', default='6d'); sub.add_argument('--vault-remote')
            sub.add_argument('--publish', action='store_true'); sub.add_argument('--dry-run', action='store_true')
        if command == 'publish':
            sub.add_argument('--input'); sub.add_argument('--output'); sub.add_argument('--key-out'); sub.add_argument('--cipher')
            sub.add_argument('--remote', required=True); sub.add_argument('--vault-remote', required=True)
        if command == 'change-password': sub.add_argument('--memory-kib', type=int, default=65536); sub.add_argument('--iterations', type=int, default=3)
    args = p.parse_args(arguments)
    try:
        if args.command == 'batch-encrypt':
            from batch import batch_encrypt
            result = batch_encrypt(args.input_dir, args.output_dir, args.private_dir, args.recursive, args.dry_run)
            print(json.dumps(result, ensure_ascii=False))
            if result['errors']: p.exit(1)
            return
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
                elif args.command == 'batch-add':
                    from batch import batch_add
                    raw = batch_add(vault, args.manifest) or original
                elif args.command == 'migrate':
                    from batch import migrate
                    raw = migrate(vault, args.id, args.cipher, args.output_dir, args.name) or original
                elif args.command == 'presign':
                    from presign import sign_vault, validate_options
                    validate_options(args.source, args.remote, args.expires, args.publish, args.vault_remote)
                    replacement, report = sign_vault(vault, args.source, args.remote, args.expires, args.dry_run)
                    if replacement is not None:
                        raw = replacement; store.commit(raw, previous=original)
                    if args.publish and not args.dry_run:
                        copy_remote(args.vault, args.vault_remote, is_vault=True);report['published'] = True
                    print(json.dumps({**report, 'vault_bytes': len(raw), 'revision': parse(raw).revision}))
                    return
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
                    existing = next((f for f in vault.data['files'] if f.get('url') == args.url), None)
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


if __name__ == '__main__': raise SystemExit(main())
