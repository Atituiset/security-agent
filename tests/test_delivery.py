import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from security_agent.core.delivery import manifest, pack, sign, verify


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / 'run'
        (self.run / 'attempts' / 'A00001').mkdir(parents=True)
        (self.run / 'state.json').write_text('{"execution": "COMPLETED"}\n')
        (self.run / 'review.sarif').write_text('{"version": "2.1.0"}\n')
        (self.run / 'attempts' / 'A00001' / 'outcome.json').write_text('{"execution": "COMPLETED"}\n')
        (self.run / '.lock').write_text('')

    def test_pack_is_reproducible_and_excludes_lock(self):
        first, sums1 = pack(self.run, self.root / 'a.tar.gz')
        second, sums2 = pack(self.run, self.root / 'b.tar.gz')
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(sums1.read_text(), sums2.read_text())
        self.assertNotIn('.lock', sums1.read_text())
        self.assertEqual(len(manifest(self.run)), 3)

    def test_verify_detects_tampering_and_missing_and_extra(self):
        bundle, sums = pack(self.run, self.root / 'd.tar.gz')
        out = self.root / 'extracted'
        with tarfile.open(bundle) as tar:
            tar.extractall(out)
        ok, problems = verify(out, sums)
        self.assertTrue(ok, problems)
        (out / 'run' / 'state.json').write_text('{"execution": "HACKED"}\n')
        (out / 'run' / 'review.sarif').unlink()
        (out / 'run' / 'injected.txt').write_text('x')
        ok, problems = verify(out, sums)
        self.assertFalse(ok)
        self.assertEqual(sorted(p.split(': ')[0] for p in problems), ['extra', 'missing', 'modified'])

    @unittest.skipUnless(shutil.which('gpg'), 'gpg unavailable')
    def test_gpg_sign_and_verify_roundtrip(self):
        home = self.root / 'gnupg'
        home.mkdir(mode=0o700)
        import os
        env = {**os.environ, 'GNUPGHOME': str(home)}
        gen = subprocess.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
                              '--quick-generate-key', 'delivery-test@example.invalid', 'default', 'sign', 'never'],
                             capture_output=True, text=True, env=env)
        self.assertEqual(gen.returncode, 0, gen.stderr)
        bundle, _ = pack(self.run, self.root / 's.tar.gz')
        signature = sign(bundle, 'delivery-test@example.invalid', gpg_home=home)
        check = subprocess.run(['gpg', '--batch', '--verify', str(signature), str(bundle)],
                               capture_output=True, text=True, env=env)
        self.assertEqual(check.returncode, 0, check.stderr)
        bundle.write_bytes(bundle.read_bytes() + b' ')
        check = subprocess.run(['gpg', '--batch', '--verify', str(signature), str(bundle)],
                               capture_output=True, text=True, env=env)
        self.assertNotEqual(check.returncode, 0)


if __name__ == '__main__':
    unittest.main()
