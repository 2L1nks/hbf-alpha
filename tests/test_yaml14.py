"""YAML Alpha 1.4 integration tests; isolated temp controller DB."""
from __future__ import annotations

import json
import unittest

from test_alpha import ControllerTest
from yaml_io import parse_yaml


def sample(*, port='8080', enabled=True, rid='HBF-001', priority=100, action='drop'):
    return f'''version: 1
policies:
  - id: {rid}
    description: "Old-format TCP policy"
    enabled: {str(enabled).lower()}
    source: kali01
    destination: kali02
    protocol: tcp
    destination_port: {port}
    action: {action}
    priority: {priority}
'''


class YAML14Tests(unittest.TestCase):
    def setUp(self):
        self.t = ControllerTest('runTest')
        self.t.setUp()

    def tearDown(self):
        self.t.tearDown()

    def preview(self, text, mode='merge'):
        return self.t.post('/api/yaml/preview', {'text': text, 'mode': mode})

    def commit(self, text, mode='merge', *, token=None, confirm=None):
        if token is None:
            res = self.preview(text, mode)
            self.assertEqual(res.status_code, 200, res.text)
            token = res.json()['fingerprint']
        return self.t.post('/api/yaml/import', {
            'text': text, 'mode': mode, 'fingerprint': token,
            'confirm': confirm or ('IMPORT_YAML' if mode == 'merge' else 'REPLACE_POLICIES'),
        })

    def records(self):
        return self.t.client.get('/api/policies').json()

    def test_old_example_import_and_no_firewall_apply(self):
        text = sample()
        rev_before = self.t.client.get('/api/revisions').json()
        audit_before = self.t.client.get('/api/audit').json()
        res = self.preview(text)
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['counts']['add'], 1)
        self.assertEqual(self.records(), [])
        self.assertEqual(self.t.client.get('/api/revisions').json(), rev_before)
        self.assertEqual(self.t.client.get('/api/audit').json(), audit_before)
        res = self.commit(text, token=res.json()['fingerprint'])
        self.assertEqual(res.status_code, 200, res.text)
        policy = self.records()[0]
        self.assertEqual(policy['id'], 'HBF-001')
        self.assertEqual(policy['name'], 'HBF-001')
        self.assertEqual(policy['note'], 'Old-format TCP policy')
        self.assertEqual(policy['ports'], '8080')
        self.assertEqual(policy['enabled'], 1)
        with self.t.mod.conn() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM deployments').fetchone()[0], 0)
        self.assertEqual(self.t.client.get('/api/revisions').json()[0]['reason'], 'YAML merge import')

    def test_reject_old_ssh_rule_even_disabled(self):
        for enabled in ('true', 'false'):
            with self.subTest(enabled=enabled):
                res = self.preview(sample(port='22', enabled=enabled))
                self.assertEqual(res.status_code, 422, res.text)
                self.assertIn('22', res.json()['detail'])
                self.assertEqual(self.records(), [])

    def test_merge_update_preserves_other_policies(self):
        self.assertEqual(self.commit(sample()).status_code, 200)
        self.assertEqual(self.commit(sample(port='8443', rid='HBF-002')).status_code, 200)
        result=self.preview(sample(port='9000'), mode='merge').json()
        self.assertEqual(result['counts'], {'add':0,'update':1,'unchanged':1,'remove':0,'total':2})
        self.assertEqual(self.commit(sample(port='9000')).status_code, 200)
        self.assertEqual({r['id']:r['ports'] for r in self.records()}, {'HBF-001':'9000','HBF-002':'8443'})

    def test_replace_requires_explicit_confirmation_and_removes_missing(self):
        self.assertEqual(self.commit(sample()).status_code, 200)
        self.assertEqual(self.commit(sample(port='8443', rid='HBF-002')).status_code, 200)
        next_doc=sample(port='9000')
        view=self.preview(next_doc, mode='replace').json()
        self.assertEqual(view['changes']['remove'], ['HBF-002'])
        denied=self.commit(next_doc, mode='replace', token=view['fingerprint'], confirm='IMPORT_YAML')
        self.assertEqual(denied.status_code, 422)
        self.assertEqual(len(self.records()), 2)
        self.assertEqual(self.commit(next_doc, mode='replace', token=view['fingerprint']).status_code, 200)
        self.assertEqual([r['id'] for r in self.records()], ['HBF-001'])

    def test_stale_preview_cannot_modify_db(self):
        old=sample(port='8080')
        token=self.preview(old).json()['fingerprint']
        self.assertEqual(self.commit(sample(port='9000',rid='HBF-002')).status_code, 200)
        err=self.commit(old,token=token)
        self.assertEqual(err.status_code,409)
        self.assertEqual([r['id'] for r in self.records()], ['HBF-002'])

    def test_preview_rejects_conflicting_verdicts_within_upload(self):
        text = '''version: 1
policies:
- id: ALLOW1
  source: kali01
  destination: kali02
  protocol: tcp
  ports: "59550"
  action: accept
  priority: 100
  enabled: true
- id: DROP1
  source: kali01
  destination: kali02
  protocol: tcp
  destination_port: 59550
  action: drop
  priority: 100
  enabled: true
'''
        res=self.preview(text)
        self.assertEqual(res.status_code,422,res.text)
        self.assertEqual(self.records(),[])
        res=self.preview(text.replace('priority: 100\n  enabled: true\n','priority: 10\n  enabled: true\n',1))
        self.assertEqual(res.status_code,200,res.text)

    def test_merge_rejects_conflict_with_existing_policy(self):
        self.assertEqual(self.commit(sample(port='59550')).status_code,200)
        bad=sample(port='59550',rid='ALLOW1',action='accept')
        res=self.preview(bad)
        self.assertEqual(res.status_code,422,res.text)
        self.assertEqual(len(self.records()),1)

    def test_duplicate_mapping_keys_are_rejected(self):
        text=sample().replace('    protocol: tcp','    protocol: tcp\n    protocol: udp')
        self.assertEqual(self.preview(text).status_code,422)

    def test_unknown_fields_rejected_not_silently_ignored(self):
        self.assertEqual(self.preview(sample().replace('    protocol: tcp','    protocol: tcp\n    run: "command"')).status_code,422)

    def test_anchors_aliases_and_python_tags_rejected(self):
        alias=sample().replace('    source: kali01','    source: &s kali01\n    destination: *s').replace('    destination: kali02\n','')
        self.assertEqual(self.preview(alias).status_code,422)
        tag=sample().replace('    description: "Old-format TCP policy"','    description: !!python/object/apply:os.system ["whoami"]')
        self.assertEqual(self.preview(tag).status_code,422)

    def test_oversize_and_multidocument_rejected(self):
        self.assertEqual(self.preview('a' * 1048577).status_code,422)
        self.assertEqual(self.preview(sample() + '\n---\nversion: 1\npolicies: []\n').status_code,422)

    def test_invalid_version_and_duplicate_ids_rejected(self):
        self.assertEqual(self.preview(sample().replace('version: 1','version: true')).status_code,422)
        second=sample().split('policies:\n',1)[1]
        self.assertEqual(self.preview(sample()+second).status_code,422)

    def test_export_roundtrip_and_noop(self):
        self.assertEqual(self.commit(sample()).status_code,200)
        response=self.t.client.get('/api/yaml/export')
        self.assertEqual(response.status_code,200)
        exported=response.json()['yaml']
        self.assertEqual(parse_yaml(exported)[0]['id'],'HBF-001')
        plan=self.preview(exported).json()
        self.assertEqual(plan['counts']['unchanged'],1)
        self.assertEqual(plan['counts']['update'],0)

    def test_yaml_requires_login_and_csrf(self):
        self.assertEqual(self.t.client.post('/api/yaml/preview',json={'text':sample()}).status_code,403)
        self.assertEqual(self.t.client.get('/api/yaml/export').status_code,200)

    def test_partial_deploy_blocks_yaml(self):
        with self.t.mod.conn() as c:
            c.execute('INSERT INTO deployments VALUES (?,?,?,?,?,?)',
                      ('D-test','now','now','partial','hash','[]'))
        self.assertEqual(self.preview(sample()).status_code,409)
        self.assertEqual(self.commit(sample(),token='0'*64).status_code,409)
        self.assertEqual(self.records(),[])

    def test_schema_future_fields(self):
        text='''version: 1
policies:
- id: QA-ADVANCED
  name: CIDR-port-range
  description: "Scope the test to lab subnet"
  source: kali01
  destination: kali02
  protocol: tcp
  ports: ["60000-60004", 60010]
  source_cidrs: "192.168.100.0/24"
  enabled: false
'''
        # A typo must cause rejection, never silently become unrestricted.
        self.assertEqual(self.preview(text).status_code,422)
        text=text.replace('source_cidrs','src_cidrs')
        self.assertEqual(self.preview(text).status_code,200)


if __name__=='__main__':
    unittest.main()
