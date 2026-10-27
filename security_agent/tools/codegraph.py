"""Pinned local CodeGraph against an isolated, complete committed repository view."""
import json
import os
import signal
from pathlib import Path
import subprocess
from security_agent.core.storage import atomic_json, digest, read_json


def command(args, timeout, output):
    """Persist bytes even for nonzero exits and timeouts; never invoke a shell."""
    with output.with_suffix('.stdout').open('wb') as stdout, output.with_suffix('.stderr').open('wb') as stderr:
        try:
            proc = subprocess.Popen(args, stdout=stdout, stderr=stderr, start_new_session=True,
                                    env={**os.environ, 'DO_NOT_TRACK': '1', 'NO_COLOR': '1'})
            try:
                code = proc.wait(timeout=timeout)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                os.killpg(proc.pid, signal.SIGKILL); proc.wait()
                raise
        except subprocess.TimeoutExpired:
            return {'error': 'tool timeout', 'returncode': None}
        except OSError as exc:
            stderr.write(str(exc).encode())
            return {'error': str(exc), 'returncode': None}
    return {'returncode': code}


def manifest(project):
    # Index and all source/config files participate. Ignore Git administration only.
    return {str(p.relative_to(project)): digest(p.read_bytes())
            for p in sorted(project.rglob('*'))
            if p.is_file() and '.git' not in p.relative_to(project).parts}


class CodeGraph:
    capabilities = frozenset({"find_definition", "find_callers", "find_callees", "find_related_symbols", "find_references"})

    def __init__(self, record):
        self.record = record
        self.project = Path(record['project'])
        self.cli = Path(record['cli'])

    @classmethod
    def prepare(cls, repo, commit, cli, directory, timeout=120):
        directory = Path(directory); directory.mkdir(parents=True, exist_ok=False)
        cli = Path(cli).resolve()
        if not cli.is_file():
            raise ValueError('CodeGraph CLI does not exist')
        project = directory / 'repository'
        # Private checkout: no writes to target repo, no borrowed target index.
        steps = [(['git', 'clone', '--shared', '--no-checkout', '--', str(repo), str(project)], 'clone'),
                 (['git', '-C', str(project), '-c', 'core.hooksPath=/dev/null', 'checkout', '--detach', commit], 'checkout')]
        for args, name in steps:
            result = command(args, timeout, directory / name)
            if result.get('error') or result['returncode']:
                raise ValueError(f'CodeGraph preparation {name} failed; see {directory}')
        # Avoid following tracked symlinks outside the frozen checkout.
        if any(p.is_symlink() for p in project.rglob('*')):
            raise ValueError('CodeGraph baseline contains symlinks; indexing refused')
        result = command(['node', str(cli), 'init', str(project)], timeout, directory / 'index')
        db = project / '.codegraph/codegraph.db'
        if result.get('error') or result['returncode'] or not db.exists():
            raise ValueError(f'CodeGraph indexing failed; see {directory}')
        command(['node', str(cli), '--version'], timeout, directory / 'version')
        # Seal the entire built tool distribution, not just its entry point.
        tool_files = {str(p): digest(p.read_bytes()) for p in sorted(cli.parent.parent.rglob('*.js'))}
        record = {'project': str(project.resolve()), 'cli': str(cli), 'commit': commit,
                  'version': (directory / 'version.stdout').read_text().strip(),
                  'tool_files': tool_files, 'files': manifest(project)}
        atomic_json(directory / 'binding.json', record)
        return cls(record)

    def check(self):
        if manifest(self.project) != self.record['files']:
            raise ValueError('CodeGraph index/source baseline changed')
        if any(not Path(p).is_file() or digest(Path(p).read_bytes()) != sha
               for p, sha in self.record['tool_files'].items()):
            raise ValueError('CodeGraph tool changed')

    def query(self, operation, symbol, limit, directory, timeout):
        self.check()
        verb = {'find_definition': 'query', 'find_callers': 'callers', 'find_callees': 'callees',
                'find_related_symbols': 'query', 'find_references': 'query'}.get(operation)
        if verb is None:
            return {'status': 'unsupported', 'candidates': [], 'errors': ['use scoped source syntax']}
        result = command(['node', str(self.cli), verb, symbol, '--path', str(self.project),
                          '--limit', str(limit), '--json'], timeout, directory / 'graph')
        self.check()
        if (directory / 'graph.stdout').stat().st_size > 2_000_000:
            return {'status': 'error', 'candidates': [], 'errors': ['raw output exceeds processing budget']}
        stdout = (directory / 'graph.stdout').read_text(errors='replace')
        stderr = (directory / 'graph.stderr').read_text(errors='replace')
        try:
            if result.get('error') or result['returncode']:
                raise ValueError(result.get('error', 'nonzero tool exit'))
            data = json.loads(stdout)
            nodes = [r['node'] for r in data] if isinstance(data, list) else data[verb]
            if not isinstance(nodes, list):
                raise ValueError('unexpected CodeGraph shape')
            truncated = len(nodes) >= limit or 'truncat' in stderr.lower()
            candidates = [{'location': {'path': n.get('filePath'), 'start_line': n.get('startLine'),
                                          'end_line': n.get('endLine', n.get('startLine'))},
                           'identity': n} for n in nodes if isinstance(n, dict)]
            return {'status': 'partial', 'candidates': candidates, 'truncated': truncated,
                    'errors': ['graph resolution is best-effort'] + (['truncated'] if truncated else []),
                    'producer': 'codegraph', 'version': self.record['version']}
        except (ValueError, KeyError, TypeError) as exc:
            return {'status': 'error', 'candidates': [], 'errors': [str(exc), stderr[:2000]],
                    'producer': 'codegraph', 'version': self.record['version']}
