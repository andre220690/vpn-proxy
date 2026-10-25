import contextlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))


@unittest.skipIf(sys.platform == 'win32', 'Manager uses Linux fcntl; exercised by Ubuntu CI')
class ManagerRoutesTests(unittest.TestCase):
    def setUp(self):
        import manager
        self.m = manager
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.rules = self.root / 'rules'; self.rules.mkdir()
        self.config = self.root / 'config.json'
        self.config.write_bytes(b'old-config\n')
        state = {'wan': 'eth0', 'bridge': 'amn0', 'container_ip': '172.29.172.2',
                 'vpn_port': 1234, 'active': None, 'exits': []}
        for name, value in [('RULES', self.rules), ('CONFIG', self.config),
                            ('locked', contextlib.nullcontext)]:
            p = patch.object(manager, name, value); p.start(); self.addCleanup(p.stop)
        for name, value in [('get_state', state), ('secret', 'test-only')]:
            p = patch.object(manager, name, return_value=value); p.start(); self.addCleanup(p.stop)

    def test_validates_staged_files_then_uses_canonical_paths(self):
        import core
        with patch.object(core, 'RULES', self.rules):
            checked = []
            def run(args, **kwargs):
                if args[:2] == ['sing-box', 'check']:
                    doc = json.loads(Path(args[-1]).read_text())
                    paths = [Path(s['path']) for s in doc['route']['rule_set'] if s['tag'] != 'geoip-ru']
                    self.assertTrue(all(p.exists() and p.parent != self.rules for p in paths))
                    self.assertEqual(self.config.read_bytes(), b'old-config\n')
                    checked.append(True)
                else:
                    self.assertTrue(all((self.rules / (k + '.json')).exists() for k in self.m.KEYS))
                    doc = json.loads(self.config.read_text())
                    self.assertTrue(all(Path(s['path']).parent == self.rules
                                        for s in doc['route']['rule_set'] if s['tag'] in self.m.KEYS))
            with patch.object(self.m, 'run', side_effect=run):
                current = self.m.routes()
                saved = self.m.routes_save(dict(current, rules=dict(current['rules'], **{'manual-exit': ['8.8.8.8']})))
            self.assertEqual(checked, [True])
            self.assertEqual(saved['rules']['manual-exit'], ['8.8.8.8/32'])

    def test_restart_failure_restores_original_config_and_rules_before_restarting(self):
        current = self.m.routes(); attempts = []
        def run(args, **kwargs):
            if args[:2] == ['sing-box', 'check']: return
            if args[:2] == ['systemctl', 'restart']:
                attempts.append(True)
                if len(attempts) == 1: raise OSError('service failed')
                self.assertEqual(self.config.read_bytes(), b'old-config\n')
                self.assertTrue(all(not (self.rules / (k + '.json')).exists() for k in self.m.KEYS))
        with patch.object(self.m, 'run', side_effect=run), self.assertRaises(self.m.ConfigError):
            self.m.routes_save(current)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(self.m.routes(), current)

    def test_failed_save_preserves_live_selection_after_switch_without_restart(self):
        # The on-disk default is A, while state/live selector have switched to B.
        old = {'outbounds': [{'type':'selector','tag':'exit-default',
                             'outbounds':['exit-a','exit-b'],'default':'exit-a'}]}
        self.config.write_text(json.dumps(old))
        state = {'active':'b'}
        current = self.m.routes(); attempts = []
        def run(args, **kwargs):
            if args[:2] == ['systemctl','restart']:
                attempts.append(True)
                if len(attempts) == 1: raise OSError('restart failed')
                recovered = json.loads(self.config.read_text())
                self.assertEqual(recovered['outbounds'][0]['default'], 'exit-b')
        with patch.object(self.m,'get_state',return_value=state), \
             patch.object(self.m,'check_config',return_value='new-config'), \
             patch.object(self.m,'run',side_effect=run), self.assertRaises(self.m.ConfigError):
            self.m.routes_save(current)
        self.assertEqual(len(attempts),2)
        self.assertEqual(json.loads(self.config.read_text())['outbounds'][0]['default'],'exit-b')


if __name__ == '__main__': unittest.main()
