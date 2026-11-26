"""Run: python -m unittest discover -s tests -v (with FastAPI dependencies installed)."""
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_agent():
    import importlib.machinery
    loader = importlib.machinery.SourceFileLoader('hbf_agent_under_test', str(ROOT/'agent/hbf-alpha-agent'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class AgentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent=load_agent()

    def valid(self):
        return {'version':1,'host_ip':'192.168.100.20','rules':[
            {'id':'P-abc','source':'192.168.100.10','destination':'192.168.100.20',
             'proto':'tcp','port':9090,'direction':'input'}]}

    def test_valid_nft_is_scoped_to_single_table(self):
        with patch.object(self.agent,'local_ipv4',return_value=True):
            rules=self.agent.validate(self.valid())
        nft=self.agent.compile_nft(rules)
        self.assertIn('table inet hbf_alpha',nft)
        self.assertIn('tcp dport 9090 counter drop comment "HBF:P-abc"',nft)
        self.assertNotIn('flush ruleset',nft)
        self.assertNotIn('table inet hbf_block',nft)

    def test_rejects_admin_port_and_wrong_direction(self):
        doc=self.valid()
        doc['rules'][0]['port']=22
        with patch.object(self.agent,'local_ipv4',return_value=True),self.assertRaises(ValueError):
            self.agent.validate(doc)
        doc=self.valid()
        doc['rules'][0]['direction']='output'
        with patch.object(self.agent,'local_ipv4',return_value=True),self.assertRaises(ValueError):
            self.agent.validate(doc)

    def test_rejects_command_injection(self):
        doc=self.valid()
        doc['rules'][0]['id']='x"; flush ruleset;'
        with patch.object(self.agent,'local_ipv4',return_value=True),self.assertRaises(ValueError):
            self.agent.validate(doc)
        doc=self.valid()
        doc['rules'][0]['proto']='tcp;flush'
        with patch.object(self.agent,'local_ipv4',return_value=True),self.assertRaises(ValueError):
            self.agent.validate(doc)

    def test_rejects_extra_script_fields(self):
        doc=self.valid()
        doc['run']='rm -rf /'
        with patch.object(self.agent,'local_ipv4',return_value=True),self.assertRaises(ValueError):
            self.agent.validate(doc)


class ControllerTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        home=Path(self.temp.name)
        registry=home/'hosts.json'
        registry.write_text(json.dumps([
            {'id':'kali01','ip':'192.168.100.10','label':'Kali 1'},
            {'id':'kali02','ip':'192.168.100.20','label':'Kali 2'}]))
        os.environ['HBF_CONTROLLER_HOME']=str(home)
        os.environ['HBF_REGISTRY']=str(registry)
        app_path=ROOT/'controller/app.py'
        name='hbf_app_test_'+str(time.monotonic_ns())
        spec=importlib.util.spec_from_file_location(name,app_path)
        self.mod=importlib.util.module_from_spec(spec)
        sys.modules[name]=self.mod
        spec.loader.exec_module(self.mod)
        self.mod.init_db()
        from fastapi.testclient import TestClient
        self.client=TestClient(self.mod.app,base_url='http://127.0.0.1:8088')
        salt='00'*16
        with self.mod.conn() as c:
            c.execute('INSERT INTO users VALUES (?,?,?)',('admin',salt,self.mod.digest_password('testpassword123',salt)))
        r=self.client.post('/api/login',json={'username':'admin','password':'testpassword123'})
        self.assertEqual(r.status_code,200,r.text)
        self.csrf=r.json()['csrf']

    def tearDown(self):
        # Worker may still be writing an audit record after its status changed;
        # do not delete its temporary DB while the background thread runs.
        deadline = time.monotonic() + 10
        while self.mod.LOCK.locked() and time.monotonic() < deadline:
            time.sleep(.02)
        self.client.close()
        self.temp.cleanup()

    def post(self,url,payload):
        return self.client.post(url,json=payload,headers={'x-hbf-csrf':self.csrf})

    def test_protected_mutations_and_policy_lifecycle(self):
        p={'name':'TCP9090','src':'kali01','dst':'kali02','proto':'tcp','port':9090,'enabled':True,'note':''}
        self.assertEqual(self.client.post('/api/policies',json=p).status_code,403)
        resp=self.post('/api/policies',p)
        self.assertEqual(resp.status_code,200,resp.text)
        self.assertEqual(self.post('/api/policies',p).status_code,409)
        preview=self.client.get('/api/preview').json()
        self.assertEqual(sum(x['rule_count'] for x in preview['targets']),2)
        self.assertEqual(self.post('/api/policies',{**p,'port':22}).status_code,422)
        self.assertEqual(self.client.get('/api/export').json()['schema'],'hbf-alpha-2')
        rid=resp.json()['id']
        delete=self.client.delete('/api/policies/'+rid,headers={'x-hbf-csrf':self.csrf})
        self.assertEqual(delete.status_code,200)
        rev=self.client.get('/api/revisions').json()
        self.assertTrue(rev)

    def test_enrollment_required_and_host_delete_stays_deleted(self):
        p={'id':'rogue','label':'rogue','grp':'lab','enabled':True}
        self.assertEqual(self.post('/api/hosts',p).status_code,422)
        self.assertEqual(self.client.delete('/api/hosts/kali02',headers={'x-hbf-csrf':self.csrf}).status_code,200)
        self.mod.init_db()
        self.assertNotIn('kali02',[h['id'] for h in self.client.get('/api/hosts').json()])

    def test_deploy_happy_path_with_mocked_agents(self):
        policy={'name':'TCP9090','src':'kali01','dst':'kali02','proto':'tcp','port':9090,'enabled':True,'note':''}
        self.assertEqual(self.post('/api/policies',policy).status_code,200)
        self.mod.agent=lambda h,op: json.dumps({'state':'CLEAN','schema':3,'table_exists':False,'boot_policy':False}) if op=='status' else op.upper()
        self.mod.ssh=lambda h,*cmd,**kw: 'UPLOADED'
        preview=self.client.get('/api/preview').json()
        ready=self.client.get('/api/preflight').json()
        self.assertTrue(ready['ready'],ready)
        result=self.post('/api/deploy',{'fingerprint':preview['fingerprint'],'confirm':'DEPLOY'})
        self.assertEqual(result.status_code,200,result.text)
        job=result.json()['job_id']
        for _ in range(150):
            status=self.client.get('/api/deployments/'+job).json()
            if status['state']!='running':
                break
            time.sleep(.02)
        self.assertEqual(status['state'],'success',status)
        self.assertTrue(any('COMMIT kali02' in x['message'] for x in status['logs']))

    def test_partial_deploy_requires_reconciliation(self):
        policy={'name':'TCP9090','src':'kali01','dst':'kali02','proto':'tcp','port':9090,'enabled':True,'note':''}
        self.assertEqual(self.post('/api/policies',policy).status_code,200)
        def op(h,kind):
            if kind=='status':
                return json.dumps({'state':'CLEAN','schema':3})
            if kind=='commit' and h['id']=='kali02':
                raise RuntimeError('Simulated second-node COMMIT failure')
            return kind.upper()
        self.mod.agent=op
        self.mod.ssh=lambda h,*cmd,**kw: 'UPLOADED'
        preview=self.client.get('/api/preview').json()
        result=self.post('/api/deploy',{'fingerprint':preview['fingerprint'],'confirm':'DEPLOY'})
        self.assertEqual(result.status_code,200,result.text)
        job=result.json()['job_id']
        for _ in range(150):
            status=self.client.get('/api/deployments/'+job).json()
            if status['state']!='running':
                break
            time.sleep(.02)
        self.assertEqual(status['state'],'partial',status)
        self.assertEqual(self.client.get('/api/preflight').json()['ready'],False)
        r=self.post('/api/reconcile/'+job,{'confirm':'ACK_PARTIAL'})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.client.get('/api/deployments/'+job).json()['state'],'reconciled')

    def test_import_rejects_duplicate_and_protected_ports(self):
        r=self.post('/api/import',{'schema':'hbf-alpha-1','policies':[
            {'id':'P-1','name':'BAD','src':'kali01','dst':'kali02','proto':'tcp','port':22,'enabled':True,'note':''}]})
        self.assertEqual(r.status_code,422)


if __name__=='__main__':
    unittest.main()
