"""Private NAS batch state and opaque ES3VID01 copies. No network clients."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

import encrypt
import vault

MAX_MANIFEST = 16 * 1024 * 1024
ID = re.compile(r'[a-f0-9]{32}')
HASH = re.compile(r'[a-f0-9]{64}')


@contextmanager
def directory(path, create=False, private=False):
    """Open each directory component without following symlinks; pin the result."""
    path = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if create:
                try: os.mkdir(part, 0o700, dir_fd=fd); os.fsync(fd)
                except FileExistsError: pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        info = os.fstat(fd)
        if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise vault.VaultError('Private directory must be owned by you with mode 0700')
        if create and (info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022):
            raise vault.VaultError('Output directory must not be group/world writable')
        yield fd
    finally: os.close(fd)


def child_dir(fd, name, private=True):
    try: os.mkdir(name, 0o700, dir_fd=fd); os.fsync(fd)
    except FileExistsError: pass
    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
    info = os.fstat(child)
    if info.st_uid != os.getuid() or info.st_mode & (0o077 if private else 0o022):
        os.close(child); raise vault.VaultError('Unsafe managed directory')
    return child


@contextmanager
def read_file(fd, relative):
    vault.relative_name(relative)
    parent = os.dup(fd)
    try:
        parts = relative.split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = child
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(file_fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise vault.VaultError('Expected a regular file, not a link or device')
            yield stream
    finally: os.close(parent)


def read_bytes(fd, relative, limit):
    with read_file(fd, relative) as stream:
        if os.fstat(stream.fileno()).st_size > limit: raise vault.VaultError('Local metadata exceeds size limit')
        raw = stream.read(limit + 1)
    if len(raw) > limit: raise vault.VaultError('Local metadata exceeds size limit')
    return raw


def json_bytes(data):
    raw = json.dumps(data, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(raw) > MAX_MANIFEST: raise vault.VaultError('Manifest exceeds size limit')
    return raw


def read_json(fd, name, limit=MAX_MANIFEST):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise vault.VaultError('Duplicate JSON field')
            result[key] = value
        return result
    try:
        return json.loads(read_bytes(fd, name, limit).decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(vault.VaultError('Invalid JSON number')))
    except (UnicodeError, ValueError, RecursionError):
        raise vault.VaultError('Invalid private JSON metadata') from None


def stamp(info):
    return {name: getattr(info, 'st_' + name) for name in ('dev', 'ino', 'size', 'mtime_ns', 'ctime_ns')}


def fingerprint(fd, name):
    with read_file(fd, name) as src:
        before = stamp(os.fstat(src.fileno())); digest = hashlib.sha256()
        while block := src.read(encrypt.CHUNK): digest.update(block)
        if stamp(os.fstat(src.fileno())) != before: raise vault.VaultError('Source changed while reading')
    return {**before, 'sha256': digest.hexdigest()}


def validate_record(item):
    if not isinstance(item, dict) or set(item) != {'id', 'name', 'object_key', 'key_file', 'source', 'cipher_sha256'}:
        raise vault.VaultError('Invalid Manifest record')
    vault.relative_name(item['name'])
    if (item['object_key'] != vault.object_key(item['id']) or item['key_file'] != f"keys/{item['id']}.key" or
            not isinstance(item['cipher_sha256'], str) or not HASH.fullmatch(item['cipher_sha256'])):
        raise vault.VaultError('Manifest paths must match the canonical File ID')
    source = item['source']
    if (not isinstance(source, dict) or set(source) != {'dev', 'ino', 'size', 'mtime_ns', 'ctime_ns', 'sha256'} or
            any(type(source[k]) is not int for k in source if k != 'sha256') or
            any(source[k] < 0 for k in ('dev', 'ino', 'size')) or
            not isinstance(source['sha256'], str) or not HASH.fullmatch(source['sha256'])):
        raise vault.VaultError('Invalid source fingerprint')
    return item


def manifest(fd):
    data = read_json(fd, 'manifest.json')
    if (not isinstance(data, dict) or set(data) != {'version', 'files'} or type(data['version']) is not int or
            data['version'] != 2 or not isinstance(data['files'], list) or len(data['files']) > vault.MAX_FILES):
        raise vault.VaultError('Unsupported Manifest')
    ids, names = set(), set()
    for item in data['files']:
        validate_record(item)
        if item['id'] in ids or item['name'] in names: raise vault.VaultError('Conflicting Manifest ID or name')
        ids.add(item['id']); names.add(item['name'])
    return data


def key_text(fd, name):
    try:
        text = read_bytes(fd, name, 128).decode('ascii').strip(); vault.file_key(text); return text
    except (UnicodeError, ValueError): raise vault.VaultError('Invalid private key file') from None


def verify_record(item, private_fd, output_fd):
    key = key_text(private_fd, item['key_file'])
    with read_file(output_fd, item['object_key']) as src:
        info = vault.verify_video(src, key, details=True)
    if (info['id'] != item['id'] or info['size'] != item['source']['size'] or
            info['plain_sha256'] != item['source']['sha256'] or info['cipher_sha256'] != item['cipher_sha256']):
        raise vault.VaultError('Manifest, key, File ID and ciphertext do not match')
    return key


def copy_unique(src, target_fd, name, expected_hash, recover=False):
    """Publish a complete copy atomically without replacing an existing inode."""
    try:
        with read_file(target_fd, name) as existing:
            digest = hashlib.sha256()
            while block := existing.read(encrypt.CHUNK): digest.update(block)
            if not recover or digest.hexdigest() != expected_hash:
                raise vault.VaultError('Object ID/path collision; refusing overwrite')
        return
    except FileNotFoundError: pass
    tmp = '.copy-' + secrets.token_hex(16) + '.tmp'
    file_fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target_fd)
    try:
        with os.fdopen(file_fd, 'wb') as dst:
            src.seek(0); digest = hashlib.sha256()
            while block := src.read(encrypt.CHUNK): dst.write(block); digest.update(block)
            if digest.hexdigest() != expected_hash: raise vault.VaultError('Source changed during copy')
            dst.flush(); os.fsync(dst.fileno())
        os.link(tmp, name, src_dir_fd=target_fd, dst_dir_fd=target_fd, follow_symlinks=False)
        os.fsync(target_fd)
    finally:
        try: os.unlink(tmp, dir_fd=target_fd)
        except FileNotFoundError: pass


def cleanup_stage(staging_fd, name):
    if not re.fullmatch(r'txn-[a-f0-9]{32}', name): raise vault.VaultError('Invalid transaction path')
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=staging_fd)
    try:
        for file in ('video.enc', 'video.key'):
            try: os.unlink(file, dir_fd=fd)
            except FileNotFoundError: pass
    finally: os.close(fd)
    os.rmdir(name, dir_fd=staging_fd); os.fsync(staging_fd)


def cleanup_copies(fd):
    for name in os.listdir(fd):
        if re.fullmatch(r'\.copy-[a-f0-9]{32}\.tmp', name): os.unlink(name, dir_fd=fd)
    os.fsync(fd)


def public_layout(fd):
    """Refuse a mixed directory that an operator might upload recursively."""
    if any(name != 'objects' for name in os.listdir(fd)):
        raise vault.VaultError('Ciphertext output may contain only objects/; never mix keys, Manifest or source files into the upload directory')
    try: objects = os.open('objects', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
    except FileNotFoundError: return
    try:
        for name in os.listdir(objects):
            if (not re.fullmatch(r'(?:[a-f0-9]{32}\.enc|\.copy-[a-f0-9]{32}\.tmp)', name) or
                    not stat.S_ISREG(os.stat(name, dir_fd=objects, follow_symlinks=False).st_mode)):
                raise vault.VaultError('Upload objects/ must contain only regular opaque ciphertext files, never links or private files')
    finally: os.close(objects)


def write_manifest(store, data):
    raw = json_bytes(data)
    # Validate on read as well; the previous complete JSON is the recoverable backup.
    store._write('manifest.json.bak', read_bytes(store.fd, 'manifest.json', MAX_MANIFEST))
    store._write('manifest.json', raw)


def finish_pending(store, data, source_fd, output_fd, keys_fd, staging_fd):
    pending = read_json(store.fd, '.pending.json')
    if (not isinstance(pending, dict) or set(pending) != {'version', 'stage', 'record'} or
            type(pending['version']) is not int or pending['version'] != 1):
        raise vault.VaultError('Invalid pending transaction')
    item = validate_record(pending['record']); stage = pending['stage']
    if not isinstance(stage, str) or not re.fullmatch(r'txn-[a-f0-9]{32}', stage):
        raise vault.VaultError('Invalid pending transaction path')
    if fingerprint(source_fd, item['name']) != item['source']:
        raise vault.VaultError('Pending source changed; recovery requires the original stable source')
    stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=staging_fd)
    objects_fd = child_dir(output_fd, 'objects', private=False)
    try:
        key = key_text(stage_fd, 'video.key')
        with read_file(stage_fd, 'video.enc') as src:
            details = vault.verify_video(src, key, details=True)
            if (details['id'] != item['id'] or details['plain_sha256'] != item['source']['sha256'] or
                    details['cipher_sha256'] != item['cipher_sha256']):
                raise vault.VaultError('Pending ciphertext failed verification')
            with read_file(stage_fd, 'video.key') as key_src:
                key_hash = hashlib.sha256(key_src.read(129)).hexdigest()
                copy_unique(key_src, keys_fd, item['id'] + '.key', key_hash, recover=True)
            copy_unique(src, objects_fd, item['id'] + '.enc', item['cipher_sha256'], recover=True)
        verify_record(item, store.fd, output_fd)
        existing = next((f for f in data['files'] if f['id'] == item['id'] or f['name'] == item['name']), None)
        if existing != item:
            if existing: raise vault.VaultError('Pending record conflicts with Manifest')
            if len(data['files']) >= vault.MAX_FILES: raise vault.VaultError('Too many Manifest records')
            data['files'].append(item); write_manifest(store, data)
        os.unlink('.pending.json', dir_fd=store.fd); os.fsync(store.fd)
        cleanup_stage(staging_fd, stage)
    finally: os.close(objects_fd); os.close(stage_fd)


def binding(fd):
    data = read_json(fd, '.batch.json', 16384)
    if (not isinstance(data, dict) or set(data) != {'version', 'input_dir', 'output_dir'} or
            type(data['version']) is not int or data['version'] != 1 or
            any(not isinstance(data[k], str) or not os.path.isabs(data[k]) for k in ('input_dir', 'output_dir'))):
        raise vault.VaultError('Missing/invalid trusted NAS batch layout')
    return data


def require_fresh_state(fd, names):
    for name in names:
        try: os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError: continue
        raise vault.VaultError('Incomplete batch metadata; restore the trusted private-directory backup instead of initializing over it')


def scan(source, recursive):
    names = []
    def fail(error): raise error
    for root, dirs, files in os.walk(source, followlinks=False, onerror=fail):
        dirs[:] = sorted(d for d in dirs if not (Path(root) / d).is_symlink()) if recursive else []
        for file in sorted(files):
            if Path(file).suffix.lower() == '.mp4':
                name = (Path(root) / file).relative_to(source).as_posix()
                vault.relative_name(name); names.append(name)
                if len(names) > vault.MAX_FILES: raise vault.VaultError('Too many input files')
    return names


def batch_encrypt(input_dir, output_dir, private_dir, recursive=False, dry_run=False):
    source, output, private = [Path(os.path.abspath(p)) for p in (input_dir, output_dir, private_dir)]
    for a, b in ((source, output), (source, private), (output, private)):
        if a == b or a in b.parents or b in a.parents:
            raise vault.VaultError('Input, ciphertext output and private directories must be separate, without overlap')
    with directory(source) as source_fd:
        names = scan(source, recursive)
        result = {'scanned': len(names), 'encrypted': 0, 'skipped': 0, 'recovered': 0, 'errors': 0, 'dry_run': dry_run}
        if dry_run:
            for name in names: print(f'Would verify/encrypt: {name}', file=sys.stderr)
            return result
        with directory(private, create=True, private=True), directory(output, create=True) as output_fd:
            public_layout(output_fd)
            with vault.VaultFile(private / 'manifest.json') as store:
                wanted = {'version': 1, 'input_dir': str(source), 'output_dir': str(output)}
                try:
                    if binding(store.fd) != wanted: raise vault.VaultError('Batch directory binding differs; use the original directories')
                except FileNotFoundError:
                    require_fresh_state(store.fd, ('manifest.json', 'manifest.json.bak', '.pending.json', 'keys', '.staging'))
                    store._write('.batch.json', json_bytes(wanted), exclusive=True)
                try: data = manifest(store.fd)
                except FileNotFoundError:
                    require_fresh_state(store.fd, ('manifest.json.bak', '.pending.json', 'keys', '.staging'))
                    data = {'version': 2, 'files': []}; store._write('manifest.json', json_bytes(data), exclusive=True)
                keys_fd, staging_fd = child_dir(store.fd, 'keys'), child_dir(store.fd, '.staging')
                try:
                    objects_fd = child_dir(output_fd, 'objects', private=False)
                    try: cleanup_copies(objects_fd); cleanup_copies(keys_fd)
                    finally: os.close(objects_fd)
                    try:
                        finish_pending(store, data, source_fd, output_fd, keys_fd, staging_fd)
                        result['recovered'] += 1
                    except FileNotFoundError:
                        # Only absence of the journal means there is no transaction.
                        try: os.stat('.pending.json', dir_fd=store.fd, follow_symlinks=False)
                        except FileNotFoundError: pass
                        else: raise
                    for orphan in os.listdir(staging_fd): cleanup_stage(staging_fd, orphan)
                    by_name = {f['name']: f for f in data['files']}
                    for item in data['files']:
                        if item['name'] not in names:
                            try:
                                if fingerprint(source_fd, item['name']) != item['source']:
                                    raise vault.VaultError('Previously completed source changed')
                                verify_record(item, store.fd, output_fd)
                            except (OSError, ValueError, vault.InvalidTag) as error:
                                result['errors'] += 1; print(f"Previously completed source unavailable/invalid: {item['name']}: {error}", file=sys.stderr)
                    for index, name in enumerate(names, 1):
                        print(f'[{index}/{len(names)}] verify/encrypt: {name}', file=sys.stderr, flush=True)
                        stage = None
                        try:
                            snapshot = fingerprint(source_fd, name)
                            if name in by_name:
                                item = by_name[name]
                                if snapshot != item['source']: raise vault.VaultError('Source changed; existing record will not be overwritten')
                                verify_record(item, store.fd, output_fd); result['skipped'] += 1; continue
                            stage = 'txn-' + secrets.token_hex(16)
                            os.mkdir(stage, 0o700, dir_fd=staging_fd)
                            stage_path = private / '.staging' / stage
                            encrypt.encrypt(source / name, stage_path / 'video.enc', stage_path / 'video.key')
                            key = vault.read_key(stage_path / 'video.key')
                            details = vault.verify_video(stage_path / 'video.enc', key, details=True)
                            if snapshot != fingerprint(source_fd, name) or snapshot['sha256'] != details['plain_sha256']:
                                raise vault.VaultError('Source changed during encryption')
                            item = {'id': details['id'], 'name': name, 'object_key': vault.object_key(details['id']),
                                    'key_file': f"keys/{details['id']}.key", 'source': snapshot,
                                    'cipher_sha256': details['cipher_sha256']}
                            validate_record(item)
                            if any(f['id'] == item['id'] for f in data['files']): raise vault.VaultError('Random File ID collision')
                            for root_fd, path in ((store.fd, item['key_file']), (output_fd, item['object_key'])):
                                try: os.stat(path, dir_fd=root_fd, follow_symlinks=False)
                                except FileNotFoundError: pass
                                else: raise vault.VaultError('Object ID/path already exists; refusing overwrite')
                            if len(data['files']) >= vault.MAX_FILES: raise vault.VaultError('Too many Manifest records')
                            durable = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=staging_fd)
                            try: os.fsync(durable); os.fsync(staging_fd)
                            finally: os.close(durable)
                            store._write('.pending.json', json_bytes({'version': 1, 'stage': stage, 'record': item}), exclusive=True)
                            finish_pending(store, data, source_fd, output_fd, keys_fd, staging_fd)
                            result['encrypted'] += 1; stage = None
                        except (OSError, ValueError, vault.InvalidTag) as error:
                            result['errors'] += 1; print(f'Failed: {name}: {error}', file=sys.stderr)
                            try: os.stat('.pending.json', dir_fd=store.fd, follow_symlinks=False)
                            except FileNotFoundError:
                                if stage: cleanup_stage(staging_fd, stage)
                            else: break  # Keep the journal and its material for explicit verified recovery.
                finally: os.close(keys_fd); os.close(staging_fd)
        return result


def batch_add(opened, manifest_path):
    path = Path(os.path.abspath(manifest_path))
    if path.name != 'manifest.json': raise vault.VaultError('Use the generated private/manifest.json')
    with directory(path.parent, private=True), vault.VaultFile(path) as store:
        layout, data = binding(store.fd), manifest(store.fd)
        try: os.stat('.pending.json', dir_fd=store.fd, follow_symlinks=False)
        except FileNotFoundError: pass
        else: raise vault.VaultError('Finish the pending batch transaction before importing')
        files = list(opened.data['files'])
        with directory(layout['output_dir']) as output_fd:
            public_layout(output_fd)
            for item in data['files']:
                key = verify_record(item, store.fd, output_fd)
                record = {'id': item['id'], 'name': item['name'], 'objectKey': item['object_key'], 'key': key}
                prior = next((f for f in files if f['id'] == item['id'] or f['key'] == key), None)
                if prior == record: continue
                if prior: raise vault.VaultError('Import conflicts with an existing record; use explicit migration for legacy URLs')
                files.append(record)
        if files == opened.data['files']: return None
        return vault.update(opened, files)


def migrate(opened, record_id, cipher_path, output_dir, name=None):
    old = next((f for f in opened.data['files'] if f['id'] == record_id), None)
    if old is None: raise vault.VaultError('Record not found; legacy entries remain unchanged')
    path = Path(os.path.abspath(cipher_path))
    with directory(path.parent) as parent, read_file(parent, path.name) as src:
        info = vault.verify_video(src, old['key'], details=True)
        record = {'id': info['id'], 'name': vault.relative_name(name or old['name']),
                  'objectKey': vault.object_key(info['id']), 'key': old['key']}
        files = [record if f['id'] == record_id else f for f in opened.data['files']]
        raw = vault.update(opened, files) if files != opened.data['files'] else None
        with directory(output_dir, create=True) as output_fd:
            public_layout(output_fd)
            objects_fd = child_dir(output_fd, 'objects', private=False)
            try: copy_unique(src, objects_fd, info['id'] + '.enc', info['cipher_sha256'], recover=True)
            finally: os.close(objects_fd)
        return raw
