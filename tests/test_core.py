import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from core import (ConfigError, default_state, build_singbox, parse_peer,
                  nft_text, rules_text)

SAMPLE='''[Interface]
PrivateKey = NotARealPrivateKey
Address = 10.8.1.16/32
DNS = 1.1.1.1
Table = auto
Jc = 5
Jmin = 10
Jmax = 50
S1 = 12

[Peer]
PublicKey = NotARealPeerKey
Endpoint = 203.0.113.8:47137
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
'''

class CoreTests(unittest.TestCase):
    def setUp(self):self.s=default_state('enp3s0','amn0','172.29.172.2')
    def test_zero_exits_blocks_foreign(self):
        cfg=build_singbox(self.s,'unit-secret')
        self.assertEqual(cfg['route']['final'],'ru')
        self.assertEqual(cfg['route']['rules'][-1],{'action':'reject'})
        self.assertNotIn('exit-default',[o['tag'] for o in cfg['outbounds']])
        self.assertEqual(cfg['experimental']['clash_api']['external_controller'],'127.0.0.1:9090')
    def test_added_but_inactive_still_blocks(self):
        self.s['exits']=[{'id':'abcd','interface':'axabcd','mark':220}]
        cfg=build_singbox(self.s)
        self.assertEqual(cfg['route']['rules'][-1],{'action':'reject'})
        self.assertEqual(cfg['route']['final'],'ru')
    def test_selector_only_active_exit_for_default(self):
        self.s['exits']=[{'id':'fi','interface':'axfi','mark':220},
                         {'id':'de','interface':'axde','mark':221}]
        self.s['active']='de'
        c=build_singbox(self.s,'secret')
        sel=next(x for x in c['outbounds'] if x['tag']=='exit-default')
        self.assertEqual(sel['default'],'exit-de')
        self.assertTrue(sel['interrupt_exist_connections'])
        self.assertEqual(c['route']['final'],'exit-default')
        self.assertEqual(next(x for x in c['outbounds'] if x['tag']=='exit-fi')['routing_mark'],220)
    def test_parse_conf_table_off_and_no_dns(self):
        p=parse_peer(SAMPLE)
        self.assertEqual(p['address'],'10.8.1.16/32')
        self.assertNotIn('DNS =',p['config'])
        self.assertIn('Table = off',p['config'])
        self.assertEqual(p['config'].count('[Peer]'),1)
        self.assertIn('Jmin = 10',p['config'])
        self.assertIn('AllowedIPs = 0.0.0.0/0',p['config'])
        self.assertNotIn('::/0',p['config'])
    def test_rejects_exec_in_profile(self):
        with self.assertRaises(ConfigError):parse_peer(SAMPLE.replace('DNS = 1.1.1.1','PostUp = touch /tmp/surprise'))
    def test_requires_egress_full_route(self):
        with self.assertRaises(ConfigError):parse_peer(SAMPLE.replace('0.0.0.0/0, ::/0','8.8.8.8/32'))
    def test_scoped_nft(self):
        n=nft_text(self.s,'198.51.100.22')
        self.assertIn('iifname "amn0" ip saddr 172.29.172.2 udp sport 1234 return',n)
        self.assertIn('ip daddr 198.51.100.22 return',n)
        self.assertIn('meta mark set 100 tproxy to :2083',n)
        self.assertNotIn('flush ruleset',n)
    def test_rules(self):
        self.assertEqual(json.loads(rules_text([],False))['rules'],[])
        r=json.loads(rules_text(['example.com','*.example.org'],True))['rules'][0]
        self.assertIn('example.com',r['domain'])
        self.assertIn('.example.org',r['domain_suffix'])
    def test_duplicate_name_or_invalid_interface(self):
        with self.assertRaises(ConfigError):default_state('verylongbadinterfacename','amn0','172.29.172.2')

if __name__=='__main__':unittest.main()
