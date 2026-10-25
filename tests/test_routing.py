import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from core import ConfigError, build_singbox, default_state
from routing import normalize_routes, read_routes, save_routes


def empty():
    return {'manual-ru': [], 'manual-exit': [], 'domain-ru': [], 'domain-exit': []}


class RoutingTests(unittest.TestCase):
    def test_normalizes_and_deduplicates(self):
        p = dict(empty(), **{'manual-exit': ['8.8.8.9/24', '8.8.8.0/24'],
                            'domain-ru': [' Example.COM ', '*.ПРИМЕР.РФ', 'example.com']})
        r = normalize_routes(p)
        self.assertEqual(r['manual-exit'], ['8.8.8.0/24'])
        self.assertEqual(r['domain-ru'], ['example.com', '*.xn--e1afmkfd.xn--p1ai'])

    def test_rejects_invalid_inputs(self):
        for key, value in [('manual-ru', ['10.0.0.1']), ('manual-exit', ['::/0']),
                           ('domain-ru', ['https://example.com/path']),
                           ('domain-ru', ['bad_.example.com']),
                           ('domain-ru', ['-bad.example.com']),
                           ('domain-ru', ['1.1.1.1']), ('domain-ru', 'example.com'),
                           ('domain-ru', ['example.com\nother.com']),
                           ('manual-ru', ['0.0.0.0/0'])]:
            with self.subTest(value=value), self.assertRaises(ConfigError):
                normalize_routes(dict(empty(), **{key: value}))
        for p in [None, [], {}, dict(empty(), extra=[]), dict(empty(), **{'domain-ru': [None]})]:
            with self.subTest(payload=p), self.assertRaises(ConfigError):
                normalize_routes(p)

    def test_rejects_opposite_direction_overlaps(self):
        for a, b, left, right in [
            ('manual-ru', 'manual-exit', '8.8.8.0/24', '8.8.8.8'),
            ('domain-ru', 'domain-exit', '*.example.com', 'api.example.com'),
            ('domain-ru', 'domain-exit', '*.example.com', '*.sub.example.com'),
            ('domain-ru', 'domain-exit', 'EXAMPLE.com', 'example.com'),
        ]:
            p = empty(); p[a] = [left]; p[b] = [right]
            with self.subTest(payload=p), self.assertRaises(ConfigError):
                normalize_routes(p)

    def test_domains_override_ip_rules_and_geoip(self):
        rules = build_singbox(default_state('eth0', 'amn0', '172.29.172.2'))['route']['rules']
        tags = [r['rule_set'] for r in rules if 'rule_set' in r]
        self.assertEqual(tags, ['domain-ru', 'domain-exit', 'manual-ru', 'manual-exit', 'geoip-ru'])

    def test_size_limit(self):
        with self.assertRaises(ConfigError):
            normalize_routes(dict(empty(), **{'domain-ru': ['x.example.com'] * 501}))

    def test_transaction_and_stale_save(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            initial = read_routes(root)
            p = dict(empty(), **{'manual-exit': ['8.8.8.8']})
            def validate(stage):
                self.assertFalse((root / 'manual-exit.json').exists())
                self.assertEqual(json.loads((stage / 'manual-exit.json').read_text())['rules'],
                                 [{'ip_cidr': ['8.8.8.8/32']}])
                return 'candidate-config'
            applied = []
            saved = save_routes(root, p, initial['revision'], validate, applied.append, lambda: None)
            self.assertEqual(saved['rules']['manual-exit'], ['8.8.8.8/32'])
            self.assertEqual(applied, ['candidate-config'])
            with self.assertRaises(ConfigError):
                save_routes(root, empty(), initial['revision'], validate, applied.append, lambda: None)
            self.assertEqual(read_routes(root), saved)

    def test_failed_validation_does_not_touch_live_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); initial = read_routes(root)
            def fail(stage):
                raise ValueError('bad config')
            with self.assertRaises(ValueError):
                save_routes(root, empty(), initial['revision'], fail,
                            lambda _: self.fail('must not apply'), lambda: self.fail('must not restart'))
            self.assertEqual(list(root.iterdir()), [])

    def test_failed_apply_restores_bytes_and_missing_files_before_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = b'{"version":3,"rules":[{"domain":["example.com"]}]}\n'
            (root / 'domain-ru.json').write_bytes(old)
            (root / 'domain-ru.json').chmod(0o644)
            initial = read_routes(root); recovered = []
            def fail(config):
                raise RuntimeError('restart failed')
            def recover():
                self.assertEqual((root / 'domain-ru.json').read_bytes(), old)
                self.assertFalse((root / 'manual-exit.json').exists())
                recovered.append(True)
            with self.assertRaises(ConfigError):
                save_routes(root, empty(), initial['revision'], lambda _: 'cfg', fail, recover)
            self.assertEqual(recovered, [True])
            self.assertEqual(read_routes(root), initial)

    def test_refuses_unsupported_existing_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'domain-ru.json').write_text('{"version":3,"rules":[{"domain_regex":[".*"]}]}')
            with self.assertRaises(ConfigError):
                read_routes(root)

    def test_import_preserves_suffix_apex_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'domain-ru.json').write_text(
                '{"version":3,"rules":[{"domain_suffix":["example.com",".example.org"]}]}')
            current = read_routes(root)
            self.assertEqual(current['rules']['domain-ru'],
                             ['example.com', '*.example.com', '*.example.org'])
            save_routes(root,current['rules'],current['revision'],lambda _:None,lambda _:None,lambda:None)
            rule = json.loads((root / 'domain-ru.json').read_text())['rules'][0]
            self.assertEqual(rule['domain'], ['example.com'])
            self.assertEqual(rule['domain_suffix'], ['.example.com', '.example.org'])


if __name__ == '__main__':
    unittest.main()
