"""Signed delivery bundles: deterministic tarball + SHA256 manifest + GPG detached signature.

Hashes inside the run directory prove content matches records; the GPG signature over the
bundle proves to a third party that nothing changed after sealing. No GPG state is mutated:
signing uses the caller's gpg, verification instructions are printed for the recipient.
"""
import gzip
import hashlib
import io
import subprocess
import tarfile
from pathlib import Path

EXCLUDE = ('.lock',)


def manifest(run):
    """Sorted (relative path, sha256, size) for every file in the run directory."""
    run = Path(run).resolve()
    entries = []
    for path in sorted(p for p in run.rglob('*') if p.is_file() and p.name not in EXCLUDE):
        rel = str(path.relative_to(run))
        entries.append((rel, hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_size))
    if not entries:
        raise ValueError(f'run directory is empty: {run}')
    return entries


def pack(run, output):
    """Write a reproducible tar.gz (sorted entries, zero mtime) and its SHA256SUMS manifest."""
    run, output = Path(run).resolve(), Path(output).resolve()
    entries = manifest(run)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w|', format=tarfile.PAX_FORMAT) as tar:
                for rel, _, _ in entries:
                    data = (run / rel).read_bytes()
                    info = tarfile.TarInfo(f'{run.name}/{rel}')
                    info.size, info.mtime, info.mode = len(data), 0, 0o644
                    tar.addfile(info, io.BytesIO(data))
    sums = output.with_name(output.name + '.SHA256SUMS.txt')
    lines = [f'{digest}  {run.name}/{rel}\n' for rel, digest, _ in entries]
    sums.write_text(''.join(lines))
    return output, sums


def sign(bundle, key=None, gpg_home=None):
    """GPG detached ASCII-armored signature over the bundle; returns the .sig path."""
    bundle = Path(bundle)
    env = None
    if gpg_home:
        import os
        env = {**os.environ, 'GNUPGHOME': str(gpg_home)}
    command = ['gpg', '--batch', '--yes', '--armor', '--detach-sign']
    if key:
        command += ['--local-user', key]
    command += ['--output', str(bundle) + '.sig', str(bundle)]
    proc = subprocess.run(command, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        raise RuntimeError('gpg signing failed: ' + proc.stderr.strip().splitlines()[-1]
                           if proc.stderr.strip() else 'gpg signing failed')
    return Path(str(bundle) + '.sig')


def verify(directory, sums):
    """Check an extracted bundle against its manifest; returns (ok, problems)."""
    directory, sums = Path(directory), Path(sums)
    problems, seen = [], set()
    for line in Path(sums).read_text().splitlines():
        digest, rel = line.split(None, 1)
        path = directory / rel
        seen.add(rel)
        if not path.is_file():
            problems.append(f'missing: {rel}')
        elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            problems.append(f'modified: {rel}')
    extra = [str(p.relative_to(directory)) for p in directory.rglob('*')
             if p.is_file() and str(p.relative_to(directory)) not in seen]
    problems += [f'extra: {rel}' for rel in sorted(extra)]
    return not problems, problems
