"""Quarantine unit/integration API tests. Never invoke live nftables."""
import json
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from test_alpha import ControllerTest, load_agent


class QuarantineAgentTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = load_agent()

    def test_quarantine_has_ipv4_ipv6_default_drop_and_exact_management_exception(self):
        script = self.a.quarantine_rules('192.168.100.10')
        self.assertIn('table inet hbf_quarantine', script)
        for chain in ('input', 'output', 'forward'):
            self.assertIn('chain ' + chain, script)
        self.assertEqual(script.count('policy drop;'), 3)
        self.assertEqual(script.count('192.168.100.10'), 2)
        self.assertIn('ip saddr 192.168.100.10 tcp dport 22 accept', script)
        self.assertIn('ip daddr 192.168.100.10 tcp sport 22 accept', script)
        self.assertIn('iifname "lo" accept', script)
        self.assertIn('oifname "lo" accept', script)
        self.assertNotIn('flush ruleset', script)
        self.assertNotIn('delete table inet hbf_alpha', script)
        self.assertNotIn('icmpv6 type', script)

    def test_does_not_accept_injected_controller_addresses(self):
        for value in ('192.168.100.10; flush ruleset', '0.0.0.0',
                      '224.0.0.1', '2001:db8::1', '192.168.100.0/24'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.a.quarantine_rules(value)

    def test_quarantine_state_persisted_and_rollback_without_real_nft(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exists = [False]
            def sh(cmd, **kw):
                if cmd[:4] == ['/usr/sbin/nft', 'delete', 'table', 'inet']:
                    exists[0] = False
                return None
            def apply():
                exists[0] = True
            with patch.object(self.a, 'ROOT', root), \
                 patch.object(self.a, 'QUARANTINE_MARKER', root / 'quarantine-enabled'), \
                 patch.object(self.a, 'quarantine_table_exists', side_effect=lambda:exists[0]), \
                 patch.object(self.a, 'enforce_quarantine', side_effect=apply), \
                 patch.object(self.a, 'sh', side_effect=sh):
                self.assertEqual(self.a.quarantine_on(), 'QUARANTINED')
                self.assertTrue((root / 'quarantine-enabled').exists())
                self.assertEqual(self.a.quarantine_on(), 'ALREADY_QUARANTINED')
                self.assertEqual(self.a.quarantine_off(), 'QUARANTINE_RELEASED')
                self.assertFalse((root / 'quarantine-enabled').exists())
                self.assertFalse(exists[0])

    def test_quarantine_refuses_during_pending_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'pending').write_text('1')
            with patch.object(self.a, 'ROOT', root), \
                 patch.object(self.a, 'QUARANTINE_MARKER', root/'quarantine-enabled'):
                with self.assertRaisesRegex(ValueError, 'pending'):
                    self.a.quarantine_on()
                with self.assertRaisesRegex(ValueError, 'pending'):
                    self.a.quarantine_off()


class QuarantineControllerTests(ControllerTest):
    def agent_status(self, quarantined=False):
        return {'state': 'CLEAN', 'schema': 3, 'table_exists': True,
                'boot_policy': True, 'quarantined': quarantined,
                'quarantine_desired': quarantined}

    def test_quarantine_control_requires_csrf_and_managed_host(self):
        self.mod.agent=lambda h,op: json.dumps(self.agent_status())
        self.assertEqual(self.client.post('/api/hosts/kali02/quarantine',
                          json={'confirm':'QUARANTINE'}).status_code,403)
        self.assertEqual(self.post('/api/hosts/not-enrolled/quarantine',
                          {'confirm':'QUARANTINE'}).status_code,404)
        self.assertEqual(self.post('/api/hosts/kali02/quarantine',
                          {'confirm':'bad'}).status_code,422)

    def test_quarantine_on_off_with_mocked_remote_verification_and_audit(self):
        state={'quarantined':False}
        calls=[]
        def remote(h,op):
            calls.append((h['id'],op))
            if op == 'status':
                return json.dumps(self.agent_status(state['quarantined']))
            if op == 'quarantine-on':
                state['quarantined'] = True
                return 'QUARANTINED'
            if op == 'quarantine-off':
                state['quarantined'] = False
                return 'QUARANTINE_RELEASED'
            return op.upper()
        self.mod.agent=remote
        on=self.post('/api/hosts/kali02/quarantine',{'confirm':'QUARANTINE'})
        self.assertEqual(on.status_code,200,on.text)
        self.assertTrue(on.json()['quarantined'])
        self.assertIn(('kali02','quarantine-on'),calls)
        self.assertFalse(self.client.get('/api/preflight').json()['ready'])
        preview=self.client.get('/api/preview').json()
        self.assertEqual(self.post('/api/deploy',{'confirm':'DEPLOY','fingerprint':preview['fingerprint']}).status_code,409)
        off=self.post('/api/hosts/kali02/quarantine',{'confirm':'RELEASE'})
        self.assertEqual(off.status_code,200,off.text)
        self.assertFalse(off.json()['quarantined'])
        self.assertTrue(self.client.get('/api/preflight').json()['ready'])
        audits=[x['action'] for x in self.client.get('/api/audit').json()]
        self.assertIn('quarantine_on',audits)
        self.assertIn('quarantine_off',audits)

    def test_partial_blocks_quarantine_changes(self):
        self.mod.agent=lambda h,op: json.dumps(self.agent_status())
        with self.mod.conn() as c:
            c.execute('INSERT INTO deployments VALUES (?,?,?,?,?,?)',
                      ('D-test','now','now','partial','hash','[]'))
        resp=self.post('/api/hosts/kali02/quarantine',{'confirm':'QUARANTINE'})
        self.assertEqual(resp.status_code,409,resp.text)
