"""Alpha 1.2 regression and safety tests (no root or live nftables needed)."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from test_alpha import ControllerTest

ROOT=Path(__file__).resolve().parents[1]


def agent_module():
    loader=importlib.machinery.SourceFileLoader('hbf_agent_alpha12',str(ROOT/'agent/hbf-alpha-agent'))
    spec=importlib.util.spec_from_loader(loader.name,loader)
    mod=importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class Alpha12AgentTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent=agent_module()

    def candidate(self,rule=None,ipv6=None):
        return {'version':2,'host_ip':'192.168.100.10','host_ipv6':ipv6,'rules':[rule or {
            'id':'P-test','direction':'output','family':'ipv4',
            'source':['192.168.100.10/32'],'destination':['192.168.100.20/32'],
            'proto':'tcp','ports':[[1000,1010],[443,443]],'action':'drop',
            'states':['new','established'],'log_drop':True,'icmp_type':'','priority':200,
        }]}

    def validate(self,doc):
        with patch.object(self.agent,'local_ipv4',return_value=True),patch.object(self.agent,'local_ip',return_value=True):
            return self.agent.validate(doc)

    def test_v2_range_logging_and_rule_not_rate_limited(self):
        rules=self.validate(self.candidate())
        script=self.agent.compile_nft(rules)
        self.assertIn('tcp dport { 443, 1000-1010 }',script)
        self.assertIn('ct state { established, new }',script)
        self.assertEqual(script.count('limit rate 3/second'),1)
        self.assertIn('comment "HBF:LOG:P-test"',script)
        self.assertIn('counter drop comment "HBF:P-test"',script)
        verdict_line=next(l for l in script.splitlines() if 'counter drop' in l)
        self.assertNotIn('limit',verdict_line)
        self.assertEqual(script.count('table inet hbf_alpha'),3)

    def test_accept_before_drop_with_different_priorities(self):
        doc=self.candidate()
        allow={**doc['rules'][0],'id':'P-allow','action':'accept','priority':10,'log_drop':False}
        block={**doc['rules'][0],'id':'P-drop','priority':200,'log_drop':False}
        doc['rules']=[block,allow]
        script=self.agent.compile_nft(self.validate(doc))
        self.assertLess(script.index('comment "HBF:P-allow"'),script.index('comment "HBF:P-drop"'))

    def test_reject_stateful(self):
        doc=self.candidate()
        doc['rules'][0].update({'action':'reject','states':['related'],'log_drop':False})
        script=self.agent.compile_nft(self.validate(doc))
        self.assertIn('ct state related counter reject with icmpx type admin-prohibited',script)

    def test_protected_port_inside_interval(self):
        for ports in ([[21,23]],[[8000,8100]],[[22,22]],[[8088,8088]]):
            with self.subTest(ports=ports):
                doc=self.candidate()
                doc['rules'][0]['ports']=ports
                with self.assertRaisesRegex(ValueError,'Protected'):
                    self.validate(doc)

    def test_port_duplicates_and_invalid_elements(self):
        for ports in ([[100,200],[200,300]],[[0,5]],[[100,65536]],[[500,400]],[['1',3]]):
            with self.subTest(ports=ports):
                doc=self.candidate();doc['rules'][0]['ports']=ports
                with self.assertRaises(ValueError): self.validate(doc)

    def test_ipv6_allow_icmp_echo_but_never_ndp(self):
        doc=self.candidate(ipv6='fd00:abcd::10')
        doc['rules'][0].update({'family':'ipv6','source':['fd00:abcd::10/128'],
            'destination':['fd00:abcd::20/128'],'proto':'icmpv6','ports':[],
            'icmp_type':'echo-request','log_drop':False})
        script=self.agent.compile_nft(self.validate(doc))
        self.assertIn('ip6 saddr fd00:abcd::10',script)
        self.assertIn('icmpv6 type echo-request',script)
        for value in ('nd-neighbor-solicit','nd-router-advert','', 'destination-unreachable'):
            with self.subTest(value=value):
                doc['rules'][0]['icmp_type']=value
                with self.assertRaises(ValueError): self.validate(doc)

    def test_icmpv4_explicit_type_required(self):
        doc=self.candidate()
        doc['rules'][0].update({'proto':'icmp','ports':[],'icmp_type':'echo-request','log_drop':False})
        script=self.agent.compile_nft(self.validate(doc))
        self.assertIn('icmp type echo-request counter drop',script.split('ct state')[0] if 'ct state' not in script else script.replace('ct state { established, new } ',''))

    def test_ipv6_requires_enrolled_and_local_address(self):
        doc=self.candidate(ipv6=None)
        doc['rules'][0].update({'family':'ipv6','source':['fd00:abcd::10/128'],
            'destination':['fd00:abcd::20/128'],'proto':'icmpv6','ports':[],'icmp_type':'echo-request','log_drop':False})
        with self.assertRaisesRegex(ValueError,'IPv6 requires'):self.validate(doc)

    def test_matching_cidr_must_contain_local_interface_ip(self):
        doc=self.candidate()
        doc['rules'][0]['source']=['10.0.1.0/24']
        with patch.object(self.agent,'local_addresses',return_value=set()):
            with self.assertRaisesRegex(ValueError,'local interface'):
                self.validate(doc)
        import ipaddress
        with patch.object(self.agent,'local_addresses',return_value={ipaddress.ip_address('10.0.1.50')}):
            self.assertEqual(self.validate(doc)[0]['source'],['10.0.1.0/24'])

    def test_unknown_json_keys_and_invalid_state_rejected(self):
        doc=self.candidate()
        doc['rules'][0]['command']='flush ruleset'
        with self.assertRaises(ValueError):self.validate(doc)
        doc=self.candidate()
        doc['rules'][0]['states']=['invalid']
        with self.assertRaises(ValueError):self.validate(doc)


class Alpha12ControllerTests(ControllerTest):
    # Subclass also reruns existing tests to ensure every new test fixture is valid.
    def test_advanced_tcp_rule_preview_and_agent_agreement(self):
        p={'name':'multi-port allow','src':'kali01','dst':'kali02',
           'family':'ipv4','action':'accept','proto':'tcp','ports':'443,5000-5005',
           'states':'new,established','priority':10,'enabled':True}
        r=self.post('/api/policies',p)
        self.assertEqual(r.status_code,200,r.text)
        preview=self.client.get('/api/preview').json()
        self.assertEqual(sum(t['rule_count'] for t in preview['targets']),2)
        self.assertTrue(all(t['host_ip'] in ('192.168.100.10','192.168.100.20') for t in preview['targets']))
        agent=agent_module()
        for target in preview['targets']:
            doc={'version':2,'host_ip':target['host_ip'],'host_ipv6':None,'rules':target['rules']}
            with patch.object(agent,'local_ipv4',return_value=True):
                clean=agent.validate(doc)
            self.assertEqual(clean[0]['action'],'accept')
            self.assertEqual(clean[0]['ports'],[[443,443],[5000,5005]])
        self.assertEqual(self.client.get('/api/export').json()['schema'],'hbf-alpha-2')

    def test_ipv6_rule_requires_enrolled_ipv6_and_icmp_type(self):
        p={'name':'ping v6','src':'kali01','dst':'kali02',
           'family':'ipv6','action':'drop','proto':'icmpv6','icmp_type':'echo-request'}
        r=self.post('/api/policies',p)
        self.assertEqual(r.status_code,422,r.text)
        self.mod.REGISTRY.write_text(json.dumps([
            {'id':'kali01','ip':'192.168.100.10','ipv6':'fd00:abcd::10'},
            {'id':'kali02','ip':'192.168.100.20','ipv6':'fd00:abcd::20'}]))
        r=self.post('/api/policies',p)
        self.assertEqual(r.status_code,200,r.text)
        data=self.client.get('/api/preview').json()
        agent=agent_module()
        for t in data['targets']:
            doc={'version':2,'host_ip':t['host_ip'],
                 'host_ipv6':'fd00:abcd::10' if t['id']=='kali01' else 'fd00:abcd::20',
                 'rules':t['rules']}
            with patch.object(agent,'local_ipv4',return_value=True),patch.object(agent,'local_ip',return_value=True):
                agent.validate(doc)

    def test_logging_only_drop_and_protected_range(self):
        base={'name':'unsafe','src':'kali01','dst':'kali02','proto':'tcp','ports':'21-23'}
        self.assertEqual(self.post('/api/policies',base).status_code,422)
        self.assertEqual(self.post('/api/policies',{**base,'ports':'8080-8090'}).status_code,422)
        self.assertEqual(self.post('/api/policies',{**base,'ports':'9090','action':'accept','log_drop':True}).status_code,422)
        self.assertEqual(self.post('/api/policies',{**base,'ports':'9090','states':'new,bad'}).status_code,422)
        self.assertEqual(self.post('/api/policies',{**base,'ports':'9090','src_cidrs':'not-a-valid-cidr'}).status_code,422)
        self.assertEqual(self.post('/api/policies',{**base,'ports':'9090','action':'reject','states':'new'}).status_code,200)

    def test_import_legacy_and_new_fields(self):
        raw={'id':'P-legacy','name':'legacy drop','src':'kali01','dst':'kali02','proto':'udp','port':5353,'enabled':True}
        r=self.post('/api/import',{'schema':'hbf-alpha-1','policies':[raw]})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.client.get('/api/policies').json()[0]['action'],'drop')
        self.assertEqual(self.client.get('/api/policies').json()[0]['ports'],'5353')
        raw.update({'id':'P-new','action':'drop','log_drop':True,'ports':'5353,5354','port':0})
        r=self.post('/api/import',{'schema':'hbf-alpha-2','policies':[raw]})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.client.get('/api/policies').json()[0]['ports'],'5353-5354' if False else '5353,5354')

    def test_edit_preserves_new_fields_and_priority(self):
        p={'name':'v2','src':'kali01','dst':'kali02','proto':'udp','ports':'1000-1010',
           'action':'drop','log_drop':True,'priority':50,'states':'new'}
        r=self.post('/api/policies',p);self.assertEqual(r.status_code,200,r.text)
        rid=r.json()['id'];old=self.client.get('/api/policies').json()[0]
        resp=self.client.put('/api/policies/'+rid,json={**old,'enabled':False},headers={'x-hbf-csrf':self.csrf})
        self.assertEqual(resp.status_code,200,resp.text)
        new=self.client.get('/api/policies').json()[0]
        self.assertEqual(new['ports'],'1000-1010')
        self.assertEqual(new['priority'],50)
        self.assertEqual(new['log_drop'],1)
        self.assertEqual(new['enabled'],0)

class Alpha12VerifyTests(TestCase):
    def setUp(self):
        self.agent=agent_module()
        import tempfile
        self.tmp=tempfile.TemporaryDirectory()
        self.root_patch=patch.object(self.agent,'ROOT',Path(self.tmp.name))
        self.root_patch.start()
        (self.agent.ROOT/'pending').write_text('1')

    def tearDown(self):
        self.root_patch.stop()
        self.tmp.cleanup()

    def test_verify_checks_log_and_drop_order_and_actions(self):
        expected=[{'id':'LOG:P-one','direction':'output','verdict':'log'},
                  {'id':'P-one','direction':'output','verdict':'drop'}]
        (self.agent.ROOT/'expected.json').write_text(json.dumps(expected))
        actual=[{'rule':{'chain':'output','comment':'HBF:LOG:P-one','expr':[{'log':{'prefix':'HBF DROP P-one'}}]}},
                {'rule':{'chain':'output','comment':'HBF:P-one','expr':[{'counter':{}},{'drop':None}]}}]
        from types import SimpleNamespace
        with patch.object(self.agent,'sh',return_value=SimpleNamespace(stdout=json.dumps({'nftables':actual}))):
            self.assertEqual(self.agent.verify(),'VERIFIED')
            actual.reverse()
            with patch.object(self.agent,'sh',return_value=SimpleNamespace(stdout=json.dumps({'nftables':actual}))):
                with self.assertRaisesRegex(ValueError,'order'):
                    self.agent.verify()

    def test_verify_denies_incorrect_live_verdict(self):
        (self.agent.ROOT/'expected.json').write_text(json.dumps([{'id':'P-one','direction':'output','verdict':'drop'}]))
        from types import SimpleNamespace
        actual=[{'rule':{'chain':'output','comment':'HBF:P-one','expr':[{'accept':None}]}}]
        with patch.object(self.agent,'sh',return_value=SimpleNamespace(stdout=json.dumps({'nftables':actual}))):
            with self.assertRaises(ValueError):self.agent.verify()


class Alpha12SafetyTests(ControllerTest):
    def test_overlap_requires_separate_priorities(self):
        broad={'name':'broad drop','src':'kali01','dst':'kali02','proto':'tcp',
               'port':5432,'action':'drop','priority':100,
               'src_cidrs':'192.168.100.0/24','dst_cidrs':'192.168.100.0/24'}
        self.assertEqual(self.post('/api/policies',broad).status_code,200)
        exception={**broad,'name':'exception','action':'accept',
                   'src_cidrs':'192.168.100.10/32','dst_cidrs':'192.168.100.20/32'}
        r=self.post('/api/policies',exception)
        self.assertEqual(r.status_code,409,r.text)
        exception['priority']=10
        r=self.post('/api/policies',exception)
        self.assertEqual(r.status_code,200,r.text)

    def test_cidr_collapse_and_port_range_canonicalization(self):
        p={'name':'expanded','src':'kali01','dst':'kali02','proto':'tcp','ports':'440-443,9000',
           'src_cidrs':'192.168.100.10/32,192.168.100.0/24'}
        r=self.post('/api/policies',p)
        self.assertEqual(r.status_code,200,r.text)
        candidate=self.client.get('/api/preview').json()['targets'][0]['rules'][0]
        self.assertEqual(candidate['source'],['192.168.100.0/24'])
        self.assertEqual(candidate['ports'],[[440,443],[9000,9000]])
