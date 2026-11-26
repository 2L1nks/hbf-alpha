"""Alpha 1.1 topology/data-upgrade regression tests: no nftables required."""
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'controller'))
from topology import build_topology


class TopologyTest(unittest.TestCase):
    def test_many_rules_aggregate_into_one_directional_edge(self):
        hosts=[dict(id='a',label='A',ip='10.0.0.1',grp='left',enabled=1),
               dict(id='b',label='B',ip='10.0.0.2',grp='right',enabled=1)]
        rules=[dict(id=f'P-{i}',name=str(i),src='a',dst='b',proto='tcp',port=9000+i,enabled=1) for i in range(100)]
        graph=build_topology(hosts,rules)
        self.assertEqual(len(graph['edges']),1)
        self.assertEqual(graph['edges'][0]['policy_count'],100)
        self.assertEqual(graph['edges'][0]['active_count'],100)
        self.assertEqual(graph['stats']['directed_pairs'],1)

    def test_opposite_direction_separate_and_disabled(self):
        hosts=[dict(id=x,label=x,ip='10.0.0.1',grp='lab',enabled=1) for x in ('a','b')]
        rules=[dict(id='A',src='a',dst='b',proto='tcp',port=443,enabled=1),
               dict(id='B',src='b',dst='a',proto='udp',port=500,enabled=0)]
        graph=build_topology(hosts,rules)
        self.assertEqual(len(graph['edges']),2)
        self.assertEqual(graph['stats']['active_policies'],1)
        self.assertEqual(graph['edges'][1]['active_count'],0)


class MigrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        root=Path(self.tmp.name)
        (root/'registry.json').write_text(json.dumps([
            {'id':'kali01','ip':'192.168.100.10'},
            {'id':'kali02','ip':'192.168.100.20'}]))
        os.environ['HBF_CONTROLLER_HOME']=str(root)
        os.environ['HBF_REGISTRY']=str(root/'registry.json')
        self.path=root/'controller.sqlite3'
        c=sqlite3.connect(self.path)
        c.executescript('''
          CREATE TABLE users(username TEXT PRIMARY KEY,salt TEXT NOT NULL,password TEXT NOT NULL);
          CREATE TABLE sessions(digest TEXT PRIMARY KEY,username TEXT NOT NULL,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
          CREATE TABLE hosts(id TEXT PRIMARY KEY,ip TEXT NOT NULL,label TEXT NOT NULL,grp TEXT NOT NULL,enabled INTEGER NOT NULL);
          CREATE TABLE policies(id TEXT PRIMARY KEY,name TEXT NOT NULL,src TEXT NOT NULL,dst TEXT NOT NULL,proto TEXT NOT NULL,port INTEGER NOT NULL,enabled INTEGER NOT NULL,note TEXT NOT NULL);
        ''')
        c.execute('INSERT INTO hosts VALUES(?,?,?,?,?)',('kali01','192.168.100.10','Kali 01','lab',1))
        c.execute('INSERT INTO policies VALUES(?,?,?,?,?,?,?,?)',('P-x','Legacy','kali01','kali02','tcp',9090,0,'Legacy note'))
        c.commit();c.close()
        name='hbf_alpha_migration_'+str(time.monotonic_ns())
        spec=importlib.util.spec_from_file_location(name,ROOT/'controller/app.py')
        self.mod=importlib.util.module_from_spec(spec)
        sys.modules[name]=self.mod
        spec.loader.exec_module(self.mod)
        self.mod.init_db()
        from fastapi.testclient import TestClient
        self.client=TestClient(self.mod.app,base_url='http://127.0.0.1:8088')
        salt='ab'*16
        with self.mod.conn() as c:
            c.execute('INSERT INTO users VALUES (?,?,?)',('admin',salt,self.mod.digest_password('adminpassword123',salt)))
        login=self.client.post('/api/login',json={'username':'admin','password':'adminpassword123'})
        self.assertEqual(login.status_code,200,login.text)
        self.csrf=login.json()['csrf']

    def tearDown(self):
        self.client.close()
        self.tmp.cleanup()

    def test_migration_preserves_records_and_is_repeatable(self):
        self.mod.init_db()
        with self.mod.conn() as c:
            h=c.execute("SELECT * FROM hosts WHERE id='kali01'").fetchone()
            p=c.execute("SELECT * FROM policies WHERE id='P-x'").fetchone()
            self.assertEqual(h['label'],'Kali 01')
            self.assertIsNone(h['vlan'])
            self.assertEqual(p['note'],'Legacy note')
            self.assertEqual(p['tags'],'')
            self.assertEqual(c.execute('SELECT count(*) FROM policies').fetchone()[0],1)
        r=self.client.get('/api/topology')
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['stats']['policies'],1)

    def test_host_metadata_and_policy_extensions(self):
        r=self.client.put('/api/hosts/kali01',json={
            'id':'kali01','label':'Security GW','grp':'MGMT','enabled':True,
            'vlan':10,'zone':'Management','role':'controller','site':'lab',
            'description':'Main firewall controller'},headers={'x-hbf-csrf':self.csrf})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.client.get('/api/hosts').json()[0]['vlan'],10)
        data={'name':'Block test','src':'kali01','dst':'kali02','proto':'tcp','port':5555,
              'enabled':True,'note':'test','tags':'alpha,lab','owner':'security','ticket':'CHG-17'}
        r=self.client.post('/api/policies',json=data,headers={'x-hbf-csrf':self.csrf})
        self.assertEqual(r.status_code,200,r.text)
        rid=r.json()['id']
        got=[x for x in self.client.get('/api/policies').json() if x['id']==rid][0]
        self.assertEqual(got['ticket'],'CHG-17')
        self.assertEqual(got['tags'],'alpha,lab')
        self.assertEqual(self.client.get('/api/preview').status_code,200)

    def test_plan_diff_unknown_then_known_after_mocked_success(self):
        response=self.client.get('/api/plan-diff')
        self.assertEqual(response.status_code,200,response.text)
        self.assertTrue(all(not x['baseline_known'] for x in response.json()['targets']))
        candidates,_=self.mod.prepare()
        with self.mod.conn() as c:
            for name,value in candidates.items():
                c.execute('INSERT INTO applied_state(host_id,candidate,updated,deployment_id) VALUES(?,?,?,?)',
                          (name,json.dumps(value,sort_keys=True),'2026-11-23T00:00:00Z','D-ok'))
        response=self.client.get('/api/plan-diff').json()
        self.assertTrue(all(x['baseline_known'] for x in response['targets']))
        self.assertTrue(all(not x['add'] and not x['remove'] for x in response['targets']))
        with self.mod.conn() as c:
            c.execute("UPDATE policies SET enabled=1 WHERE id='P-x'")
        response=self.client.get('/api/plan-diff').json()
        self.assertEqual(sum(len(x['add']) for x in response['targets']),2)
        self.assertEqual(sum(len(x['remove']) for x in response['targets']),0)

    def test_invalid_policy_logged(self):
        data={'name':'Bad','src':'kali01','dst':'kali02','proto':'tcp','port':22}
        r=self.client.post('/api/policies',json=data,headers={'x-hbf-csrf':self.csrf})
        self.assertEqual(r.status_code,422)
        audit=self.client.get('/api/audit').json()
        self.assertTrue(any(a['action']=='validation_error' for a in audit))

if __name__=='__main__':
    unittest.main()

class SelfLinkVisibilityTest(unittest.TestCase):
    def test_same_host_rules_are_in_read_only_graph(self):
        g=build_topology(
            [{'id':'h','label':'H','ip':'10.0.0.9','grp':'lab','enabled':1}],
            [{'id':'P-LOOP','src':'h','dst':'h','proto':'tcp','port':9090,'enabled':1}])
        self.assertEqual(g['stats']['directed_pairs'],1)
        self.assertEqual(g['edges'][0]['policy_count'],1)
        self.assertEqual((g['edges'][0]['source'],g['edges'][0]['target']),('h','h'))
