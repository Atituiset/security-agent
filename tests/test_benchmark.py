from copy import deepcopy
from pathlib import Path
import shutil
import subprocess
import unittest
import json
import tempfile
from security_agent.validation.benchmark import baseline_observation, load_corpus, score


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.corpus=load_corpus('benchmarks/corpus.json')
    def row(self,cid,verdict,execution='COMPLETED',system='security-agent',repeat=1):
        case=next(c for c in self.corpus['cases'] if c['id']==cid)
        return {'case_id':cid,'verdict':verdict,'execution':execution,'system':system,'repeat':repeat,
                'sources':case['sources'],'confirmations':[{'file':case['file'],'line':case['sink_line']}] if verdict=='CONFIRMED' else []}
    def test_failures_and_abstentions_cannot_improve_recall(self):
        result=score(self.corpus,[self.row('C001','CONFIRMED'),self.row('C003','UNKNOWN','FAILED'),self.row('C005','UNKNOWN')])
        self.assertAlmostEqual(result['systems']['security-agent']['positive_recall_including_failures'],1/3)
        self.assertFalse(result['superiority_established'])
    def test_unknown_is_not_resolved_negative_or_correct_failure(self):
        r=score(self.corpus,[self.row('C002','UNKNOWN'),self.row('C008','UNKNOWN','TIMED_OUT')])['systems']['security-agent']
        self.assertEqual(r['resolved_negative_rate'],0)
        self.assertEqual(r['exact_three_way_accuracy'],0)
    def test_empty_report_is_not_a_correct_negative(self):
        r=score(self.corpus,[self.row('C002','UNKNOWN')])['systems']['security-agent']
        self.assertEqual(r['negative_false_positive_rate'],0)
        self.assertEqual(r['resolved_negative_rate'],0)
    def test_correct_finding_in_incomplete_trial_is_not_false_positive(self):
        r=score(self.corpus,[self.row('C001','CONFIRMED','BUDGET_EXHAUSTED')])['systems']['security-agent']
        self.assertEqual(r['counts']['false_positive_findings'],0)
        self.assertEqual(r['counts']['correct_findings_in_incomplete_trials'],1)
        self.assertEqual(r['positive_recall_including_failures'],0)
        self.assertEqual(r['exact_three_way_accuracy'],0)
    def test_extra_wrong_finding_prevents_exact_trial_credit(self):
        row=self.row('C001','CONFIRMED')
        row['confirmations'].append({'file':'main.cpp','line':1})
        r=score(self.corpus,[row])['systems']['security-agent']
        self.assertEqual(r['positive_recall_including_failures'],1)
        self.assertEqual(r['counts']['false_positive_findings'],1)
        self.assertEqual(r['exact_three_way_accuracy'],0)
    def test_mismatched_sources_or_duplicate_trials_rejected(self):
        row=self.row('C001','CONFIRMED')
        with self.assertRaises(ValueError):score(self.corpus,[row,row])
        row=deepcopy(row);row['sources']['main.cpp']='different'
        with self.assertRaises(ValueError):score(self.corpus,[row])
    def test_unpaired_or_varying_runs_not_hidden(self):
        rows=[self.row('C001','CONFIRMED'),self.row('C001','UNKNOWN',repeat=2),self.row('C001','CONFIRMED',system='review-skills')]
        r=score(self.corpus,rows)
        self.assertFalse(r['paired_panel'])
        self.assertEqual(r['systems']['security-agent']['inconsistent_repeated_cases'],1)
    def baseline_run(self,root,case,*,topology_verified,report=None,execution='COMPLETED'):
        repo=root/'repository';host=root/'host'
        session=repo/'.review'/'sessions'/'review-synthetic'
        shutil.copytree(Path('benchmarks')/case['source_dir'],repo)
        session.mkdir(parents=True);host.mkdir(parents=True)
        if report is not None:
            out=session/'output';out.mkdir()
            (out/'findings.json').write_text(json.dumps(report))
        (host/'hooks.jsonl').write_text('{"hook_event_name":"SubagentStart"}\n'*5)
        (host/'topology.json').write_text(json.dumps({'topology_verified':topology_verified,'workers':[]}))
        (host/'request.json').write_text(json.dumps({'file':case['file'],'function':case['function'],
            'model':'m','timeout':1,'usd':1,'package_hashes':{}}))
        (host/'receipt.json').write_text(json.dumps({'execution':execution,
            'topology_verified':topology_verified,'cost_usd':0.5}))
        return root
    def report(self,case,*,confirmed=0,excluded=0,unresolved=0,findings=(),status='completed'):
        return {'status':status,'findings':[{'location':{'path':f[0],'start_line':f[1]}} for f in findings],
                'coverage':{'scenario_counts':{'confirmed':confirmed,'excluded':excluded,'unresolved':unresolved}}}
    def test_baseline_observation_requires_verified_topology(self):
        case=next(c for c in self.corpus['cases'] if c['id']=='C001')
        with tempfile.TemporaryDirectory() as d:
            run=self.baseline_run(Path(d),case,topology_verified=False,
                report=self.report(case,confirmed=1,findings=[(case['file'],case['sink_line'])]))
            row=baseline_observation(case,run)
            self.assertEqual(row['execution'],'FAILED')
            self.assertEqual(row['verdict'],'UNKNOWN')
            self.assertEqual(row['confirmations'],[])
            self.assertEqual(row['system'],'review-skills')
            self.assertEqual(row['calls'],5)
    def test_baseline_observation_verdicts(self):
        case=next(c for c in self.corpus['cases'] if c['id']=='C001')
        with tempfile.TemporaryDirectory() as d:
            d=Path(d)
            hit=self.baseline_run(d/'hit',case,topology_verified=True,
                report=self.report(case,confirmed=1,findings=[(case['file'],case['sink_line'])]))
            self.assertEqual(baseline_observation(case,hit)['verdict'],'CONFIRMED')
            excluded=self.baseline_run(d/'excluded',case,topology_verified=True,
                report=self.report(case,excluded=2))
            self.assertEqual(baseline_observation(case,excluded)['verdict'],'REJECTED')
            unresolved=self.baseline_run(d/'unresolved',case,topology_verified=True,
                report=self.report(case,unresolved=1))
            self.assertEqual(baseline_observation(case,unresolved)['verdict'],'UNKNOWN')
    def test_baseline_observation_rejects_source_mismatch(self):
        case=next(c for c in self.corpus['cases'] if c['id']=='C001')
        with tempfile.TemporaryDirectory() as d:
            run=self.baseline_run(Path(d),case,topology_verified=True)
            (run/'repository'/'main.cpp').write_text('int main(){return 0;}\n')
            with self.assertRaises(ValueError):baseline_observation(case,run)
    @unittest.skipUnless(shutil.which('g++'),'g++ unavailable')
    def test_all_fixture_translation_units_are_valid_cpp(self):
        for case in self.corpus['cases']:
            directory=Path('benchmarks')/case['source_dir']
            for path in directory.glob('*.cpp'):
                subprocess.run(['g++','-std=c++17','-fsyntax-only',str(path)],check=True,capture_output=True)
