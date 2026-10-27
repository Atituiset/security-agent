from pathlib import Path
import re
import shutil
import subprocess
import unittest
from security_agent.validation.benchmark import load_corpus


class HeldoutCorpusTests(unittest.TestCase):
    def setUp(self):
        self.corpus = load_corpus('benchmarks/corpus-heldout.json')
    def test_corpus_loads_and_is_the_frozen_heldout_split(self):
        self.assertEqual(self.corpus['split'], 'held-out')
        self.assertEqual(self.corpus['version'], 1)
        ids = [case['id'] for case in self.corpus['cases']]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(re.fullmatch(r'H\d{3}', i) for i in ids))
    def test_composition_requirements_hold(self):
        multi = [c for c in self.corpus['cases'] if len(c['sources']) > 1]
        self.assertGreaterEqual(len(multi), 6)
        expected = [c['expected'] for c in multi]
        self.assertIn('CONFIRMED', expected)
        self.assertIn('REJECTED', expected)
        unknown = [c for c in self.corpus['cases'] if c['expected'] == 'UNKNOWN']
        self.assertGreaterEqual(len(unknown), 3)
    def test_multi_file_case_sink_lines_point_at_dereferences(self):
        deref = re.compile(r'\*\s*[A-Za-z_]|[A-Za-z_]\w*\s*->')
        for case in self.corpus['cases']:
            if len(case['sources']) <= 1:
                continue
            lines = (Path('benchmarks') / case['source_dir'] / case['file']).read_text().splitlines()
            sink = lines[case['sink_line'] - 1]
            self.assertRegex(sink, deref, f"{case['id']} sink line is not a dereference: {sink!r}")
    @unittest.skipUnless(shutil.which('g++'), 'g++ unavailable')
    def test_all_fixture_translation_units_are_valid_cpp(self):
        for case in self.corpus['cases']:
            directory = Path('benchmarks') / case['source_dir']
            for path in directory.glob('*.cpp'):
                subprocess.run(['g++', '-std=c++17', '-fsyntax-only', '-I', str(directory), str(path)],
                               check=True, capture_output=True)
