import base64
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import encrypt as enc
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def run_file(self, data):
        src, dst, key = (self.root / x for x in ('in.mp4', 'out.enc', 'out.key'))
        src.write_bytes(data)
        enc.encrypt(src, dst, key)
        raw = dst.read_bytes()
        aes = AESGCM(base64.urlsafe_b64decode(key.read_text().strip() + '='))
        return src, dst, key, raw, aes

    def decrypt(self, raw, aes):
        header = raw[:enc.HEADER.size]
        _, version, chunk, size, fid, reserved = enc.HEADER.unpack(header)
        self.assertEqual((version, chunk, reserved), (1, enc.CHUNK, bytes(8)))
        blocks = []
        for i in range(max(1, (size + chunk - 1) // chunk)):
            counter = struct.pack('>I', i)
            start = enc.HEADER.size + i * (chunk + 16)
            length = min(chunk, size - i * chunk)
            blocks.append(aes.decrypt(fid[:8] + counter, raw[start:start + length + 16], header + counter))
        self.assertEqual(len(raw), enc.HEADER.size + size + len(blocks) * 16)
        return b''.join(blocks)

    def test_roundtrip_boundaries_and_permissions(self):
        for size in (0, 1, 117, enc.CHUNK, enc.CHUNK + 21, enc.CHUNK * 2 + 91):
            with self.subTest(size=size):
                data = os.urandom(size)
                src, dst, key, raw, aes = self.run_file(data)
                self.assertEqual(self.decrypt(raw, aes), data)
                self.assertEqual(src.read_bytes(), data)
                self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                dst.unlink(); key.unlink()

    def test_tampering_wrong_key_and_header(self):
        _, _, _, raw, aes = self.run_file(os.urandom(enc.CHUNK + 20))
        for offset in (16, 24, 48, len(raw) - 1):
            damaged = bytearray(raw); damaged[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(InvalidTag):
                self.decrypt(bytes(damaged), aes)
        with self.assertRaises(InvalidTag):
            self.decrypt(raw, AESGCM(AESGCM.generate_key(256)))
        header = raw[:48]; fid = header[24:40]
        with self.assertRaises(InvalidTag):
            aes.decrypt(fid[:8] + struct.pack('>I', 1), raw[48:48 + enc.CHUNK + 16], header + struct.pack('>I', 1))

    def test_exclusive_output_and_cleanup(self):
        src = self.root / 'in'; src.write_bytes(b'hello')
        dst, key = self.root / 'out.enc', self.root / 'out.key'
        key.write_text('existing')
        with self.assertRaises(FileExistsError): enc.encrypt(src, dst, key)
        self.assertFalse(dst.exists()); self.assertEqual(key.read_text(), 'existing')
        with self.assertRaises(ValueError): enc.encrypt(src, src, key)
        key.unlink()
        with patch.object(enc.AESGCM, 'encrypt', side_effect=OSError('disk error')):
            with self.assertRaises(OSError): enc.encrypt(src, dst, key)
        self.assertFalse(dst.exists()); self.assertFalse(key.exists())

    def test_integer_limits(self):
        with self.assertRaises(ValueError): enc.make_header(2**53, bytes(16))

    def test_bounded_memory(self):
        measurements = []
        for size in (8 * 1024**2, 128 * 1024**2):
            src, dst, key = (self.root / x for x in ('large', 'large.enc', 'large.key'))
            with src.open('wb') as f: f.truncate(size)
            code = ('import encrypt,resource,sys; '
                    'resource.setrlimit(resource.RLIMIT_AS,(96*1024**2,96*1024**2)); '
                    'encrypt.encrypt(*sys.argv[1:]); '
                    'print(next(line.split()[1] for line in open("/proc/self/status") if line.startswith("VmHWM:")))')
            run = subprocess.run([sys.executable, '-c', code, str(src), str(dst), str(key)], cwd=Path(enc.__file__).parent, capture_output=True, text=True, check=True)
            measurements.append(int(run.stdout)); dst.unlink(); key.unlink()
        self.assertLess(measurements[1] - measurements[0], 32 * 1024, measurements)
        print('Peak RSS KiB (8 MiB / 128 MiB inputs):', measurements)


if __name__ == '__main__': unittest.main()
