"""HBF Alpha controller: single-operator, loopback-only web application.

Bootstrap enrolls hosts through Ansible and pins SSH host keys. The web app
cannot enroll an arbitrary remote IP, run arbitrary commands or install root
code. Agent operations are constrained by a root-owned target-side parser.
"""
from __future__ import annotations

import getpass
from contextlib import contextmanager
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from topology import build_topology, graph_stats
from yaml_io import parse_yaml, export_yaml, MAX_YAML_BYTES
from pydantic import BaseModel, Field

HOME = Path(os.getenv('HBF_CONTROLLER_HOME', '/var/lib/hbf-alpha-controller'))
DB = HOME / 'controller.sqlite3'
REGISTRY = Path(os.getenv('HBF_REGISTRY', '/etc/hbf-alpha-controller/hosts.json'))
STATIC = Path(__file__).resolve().parent / 'static'
SSH_KEY = HOME / '.ssh' / 'id_ed25519'
KNOWN = HOME / '.ssh' / 'known_hosts'
LOCK = threading.Lock()
LOGIN_ATTEMPTS = {}

app = FastAPI(title='HBF Alpha', docs_url=None, redoc_url=None, openapi_url=None)


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


@contextmanager
def conn():
    c = sqlite3.connect(DB, timeout=30)
    try:
        c.row_factory = sqlite3.Row
        c.execute('PRAGMA busy_timeout=30000')
        c.execute('PRAGMA foreign_keys=ON')
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def init_db():
    HOME.mkdir(parents=True, exist_ok=True)
    with conn() as c:
        c.executescript('''
          CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, salt TEXT NOT NULL, password TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS sessions (
            digest TEXT PRIMARY KEY, username TEXT NOT NULL, csrf TEXT NOT NULL, expires INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS hosts (
            id TEXT PRIMARY KEY, ip TEXT NOT NULL, label TEXT NOT NULL, grp TEXT NOT NULL, enabled INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS policies (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL,
            proto TEXT NOT NULL, port INTEGER NOT NULL, enabled INTEGER NOT NULL, note TEXT NOT NULL,
            FOREIGN KEY(src) REFERENCES hosts(id), FOREIGN KEY(dst) REFERENCES hosts(id));
          CREATE TABLE IF NOT EXISTS revisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT NOT NULL, actor TEXT NOT NULL,
            reason TEXT NOT NULL, snapshot TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS deployments (
            id TEXT PRIMARY KEY, created TEXT NOT NULL, updated TEXT NOT NULL,
            state TEXT NOT NULL, fingerprint TEXT NOT NULL, logs TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT NOT NULL,
            actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL);
        ''')
        # Additive, forward-only migration of Alpha 1.0 data. Never drop existing records.
        host_columns = {row[1] for row in c.execute('PRAGMA table_info(hosts)')}
        for col, ddl in (('vlan', 'INTEGER'), ('zone', "TEXT NOT NULL DEFAULT ''"),
                         ('role', "TEXT NOT NULL DEFAULT ''"), ('site', "TEXT NOT NULL DEFAULT ''"),
                         ('description', "TEXT NOT NULL DEFAULT ''")):
            if col not in host_columns:
                c.execute(f'ALTER TABLE hosts ADD COLUMN {col} {ddl}')
        policy_columns = {row[1] for row in c.execute('PRAGMA table_info(policies)')}
        for col in ('tags','owner','ticket'):
            if col not in policy_columns:
                c.execute(f"ALTER TABLE policies ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
        for col,ddl in (
            ('family', "TEXT NOT NULL DEFAULT 'ipv4'"),
            ('action', "TEXT NOT NULL DEFAULT 'drop'"),
            ('ports', "TEXT NOT NULL DEFAULT ''"),
            ('states', "TEXT NOT NULL DEFAULT ''"),
            ('src_cidrs', "TEXT NOT NULL DEFAULT ''"),
            ('dst_cidrs', "TEXT NOT NULL DEFAULT ''"),
            ('icmp_type', "TEXT NOT NULL DEFAULT ''"),
            ('priority', "INTEGER NOT NULL DEFAULT 100"),
            ('log_drop', "INTEGER NOT NULL DEFAULT 0"),
        ):
            if col not in policy_columns:
                c.execute(f'ALTER TABLE policies ADD COLUMN {col} {ddl}')
        c.execute('''CREATE TABLE IF NOT EXISTS applied_state (
            host_id TEXT PRIMARY KEY, candidate TEXT NOT NULL, updated TEXT NOT NULL, deployment_id TEXT NOT NULL)''')
    if DB.exists():
        DB.chmod(0o600)
    if REGISTRY.is_file():
        records = registry()
        with conn() as c:
            seeded = c.execute("SELECT 1 FROM metadata WHERE key='host_seeded'").fetchone()
            if not seeded:
                for host in records:
                    c.execute('INSERT OR IGNORE INTO hosts(id,ip,label,grp,enabled) VALUES (?,?,?,?,1)',
                              (host['id'], host['ip'], host.get('label', host['id']), 'lab'))
                c.execute("INSERT INTO metadata VALUES ('host_seeded', '1')")


def registry():
    records = json.loads(REGISTRY.read_text())
    if not isinstance(records, list) or not records:
        raise ValueError('Enrollment registry is empty')
    ids = set()
    ips = set()
    for r in records:
        if not re.fullmatch('[A-Za-z0-9_-]{1,48}', r['id']):
            raise ValueError('Invalid enrolled host ID')
        r['ip'] = str(ipaddress.IPv4Address(r['ip']))
        if r.get('ipv6'):
            v6 = ipaddress.IPv6Address(r['ipv6'])
            if v6.is_link_local or v6.is_multicast or v6.is_unspecified or v6.is_loopback or v6.ipv4_mapped:
                raise ValueError('Unsafe management/enrollment IPv6 address')
            r['ipv6'] = str(v6)
        else:
            r['ipv6'] = None
        if r['id'] in ids or r['ip'] in ips:
            raise ValueError('Duplicate enrolled host')
        ids.add(r['id']); ips.add(r['ip'])
    return records


def objects(table):
    with conn() as c:
        return [dict(x) for x in c.execute(f'SELECT * FROM {table} ORDER BY id')]


def hosts():
    return objects('hosts')


def policies():
    return objects('policies')


def audit(actor, action, details=''):
    with conn() as c:
        c.execute('INSERT INTO audit(created,actor,action,details) VALUES (?,?,?,?)',
                  (now(), actor, action, str(details)[:1200]))


def ensure_editable():
    with conn() as c:
        stuck = c.execute("SELECT id FROM deployments WHERE state IN ('running','partial') LIMIT 1").fetchone()
    if stuck:
        raise HTTPException(409,'Resolve active/partial deployment before editing policies or hosts: '+stuck['id'])


def revision(actor, reason):
    snap = json.dumps({'hosts':hosts(), 'policies':policies()}, sort_keys=True)
    with conn() as c:
        c.execute('INSERT INTO revisions(created,actor,reason,snapshot) VALUES (?,?,?,?)',
                  (now(), actor, reason, snap))


def digest_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 600000).hex()


def create_admin():
    init_db()
    username = input('Web admin username [admin]: ').strip() or 'admin'
    if not re.fullmatch('[a-zA-Z][a-zA-Z0-9_-]{2,31}', username):
        sys.exit('Invalid username')
    pw = getpass.getpass('New web password (min 12 characters): ')
    confirm = getpass.getpass('Repeat password: ')
    if pw != confirm or len(pw) < 12:
        sys.exit('Passwords do not match / password too short')
    salt = secrets.token_hex(16)
    with conn() as c:
        c.execute('INSERT OR REPLACE INTO users VALUES (?,?,?)',
                  (username, salt, digest_password(pw, salt)))
        c.execute('DELETE FROM sessions WHERE username=?', (username,))
    print('Web administrator configured:', username)


@app.on_event('startup')
def startup():
    init_db()
    # A killed controller cannot assert whether any remote COMMIT happened.
    # Mark orphaned in-progress jobs as requiring explicit reconciliation.
    with conn() as c:
        rows = c.execute("SELECT id, logs FROM deployments WHERE state='running'").fetchall()
        for row in rows:
            events = json.loads(row['logs'])
            events.append({'at':now(), 'message':'Controller restarted during Deploy; check agents and reconcile.'})
            c.execute("UPDATE deployments SET state='partial', logs=?, updated=? WHERE id=?",
                      (json.dumps(events[-250:]), now(), row['id']))


class Login(BaseModel):
    username: str
    password: str


def check_host(request: Request):
    if request.headers.get('host') not in ('127.0.0.1:8088', 'localhost:8088'):
        raise HTTPException(403, 'Invalid host header')
    origin = request.headers.get('origin')
    if origin and origin not in ('http://127.0.0.1:8088', 'http://localhost:8088'):
        raise HTTPException(403, 'Invalid origin')


def authorize(request: Request):
    check_host(request)
    token = request.cookies.get('hbf_session', '')
    if len(token) != 64:
        raise HTTPException(401, 'Login required')
    with conn() as c:
        record = c.execute('SELECT username,csrf FROM sessions WHERE digest=? AND expires>?',
                           (hashlib.sha256(token.encode()).hexdigest(), int(time.time()))).fetchone()
    if not record:
        raise HTTPException(401, 'Session expired')
    if request.method in ('POST','PUT','PATCH','DELETE'):
        if not hmac.compare_digest(request.headers.get('x-hbf-csrf',''), record['csrf']):
            raise HTTPException(403, 'CSRF validation failed')
    return dict(record)


@app.get('/')
def index():
    return FileResponse(STATIC / 'index.html')


@app.get('/static/{name}')
def static_file(name: str):
    if name not in ('style.css', 'app.js', 'topology.js'):
        raise HTTPException(404)
    return FileResponse(STATIC / name)


@app.post('/api/login')
def login(body: Login, request: Request):
    check_host(request)
    key = request.client.host if request.client else 'unknown'
    state = LOGIN_ATTEMPTS.get(key, [0,0.0])
    if state[1] + 600 < time.monotonic():
        state = [0, time.monotonic()]
    if state[0] >= 8:
        raise HTTPException(429, 'Too many attempts. Try again later.')
    with conn() as c:
        user = c.execute('SELECT * FROM users WHERE username=?', (body.username,)).fetchone()
    # Ensure somewhat similar work regardless of username existence.
    salt = user['salt'] if user else '00' * 16
    computed = digest_password(body.password, salt)
    if not user or not hmac.compare_digest(computed, user['password']):
        LOGIN_ATTEMPTS[key] = [state[0]+1, state[1] or time.monotonic()]
        raise HTTPException(401, 'Invalid credentials')
    LOGIN_ATTEMPTS.pop(key, None)
    token = secrets.token_hex(32)
    csrf = secrets.token_hex(24)
    with conn() as c:
        c.execute('INSERT INTO sessions VALUES (?,?,?,?)',
                  (hashlib.sha256(token.encode()).hexdigest(), user['username'], csrf,
                   int(time.time()) + 8 * 3600))
    from fastapi.responses import JSONResponse
    response = JSONResponse({'username':user['username'],'csrf':csrf})
    response.set_cookie('hbf_session', token, httponly=True, samesite='strict', secure=False,
                        path='/', max_age=8 * 3600)
    audit(user['username'], 'login')
    return response


@app.get('/api/me')
def me(user=Depends(authorize)):
    return {'username':user['username'], 'csrf':user['csrf']}


@app.post('/api/logout')
def logout(request: Request, user=Depends(authorize)):
    tok = request.cookies.get('hbf_session', '')
    with conn() as c:
        c.execute('DELETE FROM sessions WHERE digest=?', (hashlib.sha256(tok.encode()).hexdigest(),))
    from fastapi.responses import JSONResponse
    response = JSONResponse({'ok': True})
    response.delete_cookie('hbf_session', path='/')
    audit(user['username'], 'logout')
    return response


@app.get('/api/summary')
def summary(user=Depends(authorize)):
    with conn() as c:
        job = c.execute('SELECT * FROM deployments ORDER BY created DESC LIMIT 1').fetchone()
    return {'hosts':len(hosts()),'policies':len(policies()),
            'active_policies':sum(x['enabled'] for x in policies()),
            'last_deployment':dict(job) if job else None}


@app.get('/api/registry')
def enrolled(user=Depends(authorize)):
    return registry()


@app.get('/api/hosts')
def list_hosts(user=Depends(authorize)):
    return hosts()


@app.get('/api/topology')
def topology(user=Depends(authorize)):
    # The topology represents declared DROP policies, not measured network sessions.
    return build_topology(hosts(), policies())


@app.get('/api/topology/summary')
def topology_summary(user=Depends(authorize)):
    return graph_stats(build_topology(hosts(), policies()))


class HostIn(BaseModel):
    id: str = Field(min_length=1, max_length=48)
    label: str = Field(min_length=1, max_length=100)
    grp: str = Field(default='lab', max_length=64)
    vlan: int | None = Field(default=None, ge=1, le=4094)
    zone: str = Field(default='', max_length=64)
    role: str = Field(default='', max_length=64)
    site: str = Field(default='', max_length=64)
    description: str = Field(default='', max_length=300)
    enabled: bool = True


def validate_host(body):
    return next((x for x in registry() if x['id'] == body.id), None)


@app.post('/api/hosts')
def add_host(body: HostIn, user=Depends(authorize)):
    ensure_editable()
    entry = validate_host(body)
    if not entry:
        raise HTTPException(422, 'Host must first be enrolled by Ansible bootstrap')
    with conn() as c:
        try:
            c.execute('''INSERT INTO hosts(id,ip,label,grp,enabled,vlan,zone,role,site,description)
                         VALUES (?,?,?,?,?,?,?,?,?,?)''',
                      (body.id,entry['ip'],body.label,body.grp,int(body.enabled),
                       body.vlan,body.zone,body.role,body.site,body.description))
        except sqlite3.IntegrityError:
            raise HTTPException(409, 'Host already exists')
    revision(user['username'], 'host add')
    audit(user['username'], 'host_add', body.id)
    return {'ok':True}


@app.put('/api/hosts/{hid}')
def edit_host(hid: str, body: HostIn, user=Depends(authorize)):
    ensure_editable()
    if body.id != hid:
        raise HTTPException(422,'Host IDs cannot be changed')
    with conn() as c:
        count = c.execute('''UPDATE hosts SET label=?,grp=?,enabled=?,vlan=?,zone=?,
                                  role=?,site=?,description=? WHERE id=?''',
                          (body.label,body.grp,int(body.enabled),body.vlan,body.zone,
                           body.role,body.site,body.description,hid)).rowcount
    if not count:
        raise HTTPException(404, 'Unknown host')
    revision(user['username'],'host edit')
    audit(user['username'], 'host_edit', hid)
    return {'ok':True}


@app.delete('/api/hosts/{hid}')
def delete_host(hid: str, user=Depends(authorize)):
    ensure_editable()
    with conn() as c:
        if c.execute('SELECT 1 FROM policies WHERE src=? OR dst=?',(hid,hid)).fetchone():
            raise HTTPException(409,'Remove policies referencing this host first')
        count = c.execute('DELETE FROM hosts WHERE id=?',(hid,)).rowcount
    if not count:
        raise HTTPException(404,'Unknown host')
    revision(user['username'],'host delete')
    audit(user['username'], 'host_delete', hid)
    return {'ok':True}


class PolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    src: str
    dst: str
    proto: str
    port: int = 0  # legacy single port; 0 for ICMP/multi-port rules
    ports: str = Field(default='', max_length=400)
    family: str = 'ipv4'
    action: str = 'drop'
    states: str = Field(default='', max_length=48)
    src_cidrs: str = Field(default='', max_length=850)
    dst_cidrs: str = Field(default='', max_length=850)
    icmp_type: str = ''
    priority: int = 100
    log_drop: bool = False
    enabled: bool = True
    note: str = Field(default='', max_length=300)
    tags: str = Field(default='', max_length=160)
    owner: str = Field(default='', max_length=80)
    ticket: str = Field(default='', max_length=80)


POLICY_FIELDS = ('id','name','src','dst','proto','port','enabled','note',
                 'tags','owner','ticket','family','action','ports','states',
                 'src_cidrs','dst_cidrs','icmp_type','priority','log_drop')


def port_ranges(spec: str, legacy_port: int):
    tokens = (spec if spec.strip() else str(legacy_port)).split(',')
    if not 1 <= len(tokens) <= 32:
        raise ValueError('Port list must contain 1..32 values/ranges')
    result=[]
    for token in tokens:
        token=token.strip()
        if not re.fullmatch(r'[0-9]{1,5}(?:-[0-9]{1,5})?',token):
            raise ValueError('Ports must be numbers or ranges like 8000-8010')
        pair=[int(v) for v in token.split('-')]
        lo,hi=(pair[0],pair[0]) if len(pair)==1 else pair
        if not 1 <= lo <= hi <= 65535:
            raise ValueError('Invalid port range')
        if any(lo <= x <= hi for x in (22,8088)):
            raise ValueError('Management TCP/UDP ports 22 and 8088 are protected')
        result.append((lo,hi))
    result.sort()
    if any(result[i][0] <= result[i-1][1] for i in range(1,len(result))):
        raise ValueError('Overlapping/duplicate port ranges')
    return [list(x) for x in result]


def parse_cidrs(raw: str, family: int, anchor: str):
    tokens=[v.strip() for v in raw.split(',') if v.strip()] if raw.strip() else [anchor]
    if not 1 <= len(tokens) <= 16:
        raise ValueError('CIDR list size must be 1..16')
    nets=[]
    for token in tokens:
        try:
            net=ipaddress.ip_network(token,strict=False)
        except ValueError:
            raise ValueError('Invalid CIDR/IP: '+token[:70])
        if net.version != family:
            raise ValueError('CIDR family mismatch')
        if str(net) not in nets:
            nets.append(str(net))
    # Custom CIDRs may refer to a data-plane interface rather than the
    # enrollment/SSH address. The root-owned agent verifies local ownership at
    # STAGE on each endpoint before any live firewall change.
    return [str(n) for n in ipaddress.collapse_addresses(ipaddress.ip_network(v) for v in nets)]


def normalized_policy(p, excluded=None, actor='system', check_duplicates=True,
                      existing_records=None, audit_validation=True):
    try:
        hs={h['id']:h for h in hosts()}
        registered={h['id']:h for h in registry()}
        if p.src not in hs or p.dst not in hs or p.src==p.dst:
            raise ValueError('Source and destination must be different enrolled hosts')
        if p.src not in registered or p.dst not in registered:
            raise ValueError('Host not enrolled')
        if p.family not in ('ipv4','ipv6'):
            raise ValueError('Family must be ipv4 or ipv6')
        family=4 if p.family=='ipv4' else 6
        proto_set=('tcp','udp','icmp') if family==4 else ('tcp','udp','icmpv6')
        if p.proto not in proto_set:
            raise ValueError('Invalid protocol for selected IP family')
        anchors=[registered[h]['ip'] if family==4 else registered[h].get('ipv6') for h in (p.src,p.dst)]
        if not all(anchors):
            raise ValueError('IPv6 requires hbf_host_ipv6 enrollment on both hosts')
        src_cidrs=parse_cidrs(p.src_cidrs,family,anchors[0])
        dst_cidrs=parse_cidrs(p.dst_cidrs,family,anchors[1])
        if p.proto in ('tcp','udp'):
            ports=port_ranges(p.ports,p.port)
            if p.icmp_type:
                raise ValueError('ICMP type is only valid for ICMP')
        else:
            if p.ports.strip() or p.port not in (0,None):
                raise ValueError('ICMP cannot specify destination ports')
            allowed = ('echo-request','echo-reply','destination-unreachable','time-exceeded') if family==4 else ('echo-request','echo-reply')
            if p.icmp_type not in allowed:
                raise ValueError('ICMP requires a safe explicit type; IPv6 NDP/RA excluded')
            ports=[]
        if p.action not in ('accept','drop','reject'):
            raise ValueError('Unknown verdict')
        if p.log_drop and p.action!='drop':
            raise ValueError('Logging is available for DROP only')
        if type(p.priority) is not int or not 1<=p.priority<=10000:
            raise ValueError('Priority must be 1..10000 (lower number first)')
        states=[v.strip() for v in p.states.split(',') if v.strip()]
        if len(states)!=len(set(states)) or any(v not in ('new','established','related') for v in states):
            raise ValueError('Connection states: new, established, related')
        if not re.fullmatch(r'[a-zA-Z0-9_\s,.-]*',p.tags):
            raise ValueError('Unsupported policy tags')
        normalized={
            'name':p.name,'src':p.src,'dst':p.dst,'proto':p.proto,
            'port':ports[0][0] if len(ports)==1 and ports[0][0]==ports[0][1] else 0,
            'ports':','.join(str(a) if a==b else f'{a}-{b}' for a,b in ports),
            'enabled':int(p.enabled),'note':p.note,'tags':p.tags,'owner':p.owner,'ticket':p.ticket,
            'family':p.family,'action':p.action,'states':','.join(sorted(states)),
            'src_cidrs':','.join(src_cidrs) if p.src_cidrs.strip() else '',
            'dst_cidrs':','.join(dst_cidrs) if p.dst_cidrs.strip() else '',
            'icmp_type':p.icmp_type,'priority':p.priority,'log_drop':int(p.log_drop),
        }
        # Blocks ambiguous exact matches at same priority. Differing priorities deliberately
        # provide an explicit ordered exception mechanism (ACCEPT before a broad DROP).
        match=(p.src,p.dst,p.family,p.proto,tuple(src_cidrs),tuple(dst_cidrs),
               tuple(tuple(v) for v in ports),tuple(sorted(states)),p.icmp_type,p.priority)
        if check_duplicates and p.enabled:
            for old in (policies() if existing_records is None else existing_records):
                if old['id']==excluded or not old['enabled']:
                    continue
                old_obj=PolicyIn.model_validate(old)
                old_anchors=[registered[h]['ip'] if family==4 else registered[h].get('ipv6') for h in (p.src,p.dst)]
                if old_obj.src!=p.src or old_obj.dst!=p.dst or old_obj.family!=p.family or old_obj.proto!=p.proto:
                    continue
                old_src=parse_cidrs(old_obj.src_cidrs,family,old_anchors[0])
                old_dst=parse_cidrs(old_obj.dst_cidrs,family,old_anchors[1])
                old_ports=port_ranges(old_obj.ports,old_obj.port) if old_obj.proto in ('tcp','udp') else []
                old_states=tuple(sorted(v.strip() for v in old_obj.states.split(',') if v.strip()))
                old_match=(old_obj.src,old_obj.dst,old_obj.family,old_obj.proto,tuple(old_src),tuple(old_dst),
                           tuple(tuple(v) for v in old_ports),old_states,old_obj.icmp_type,old_obj.priority)
                if match==old_match:
                    raise HTTPException(409,'Duplicate active traffic match at same priority')
                # Two different verdicts matching an overlapping tuple at the
                # SAME priority have an opaque ID-dependent outcome. Require
                # explicit priority separation for ACCEPT exceptions.
                if p.action!=old_obj.action and p.priority==old_obj.priority and \
                        p.icmp_type==old_obj.icmp_type and \
                        (not states or not old_states or set(states).intersection(old_states)) and \
                        (not ports or any(a<=d and c<=b for a,b in ports for c,d in old_ports)) and \
                        any(ipaddress.ip_network(a).overlaps(ipaddress.ip_network(b))
                            for a in src_cidrs for b in old_src) and \
                        any(ipaddress.ip_network(a).overlaps(ipaddress.ip_network(b))
                            for a in dst_cidrs for b in old_dst):
                    raise HTTPException(409,'Overlapping ACCEPT/DROP/REJECT at same priority; use explicit different priorities')
        return normalized
    except ValueError as exc:
        if audit_validation:
            audit(actor,'validation_error',str(exc))
        raise HTTPException(422,str(exc))


def validate_policy(p, excluded=None, actor='system'):
    return normalized_policy(p, excluded, actor)


def insert_policy_sql():
    placeholders=','.join('?' for _ in POLICY_FIELDS)
    return 'INSERT INTO policies ('+','.join(POLICY_FIELDS)+') VALUES ('+placeholders+')'


def policy_row(rid, normalized):
    record={'id':rid,**normalized}
    return tuple(record[k] for k in POLICY_FIELDS)

@app.get('/api/policies')
def list_policies(user=Depends(authorize)):
    return policies()


@app.post('/api/policies')
def add_policy(body: PolicyIn, user=Depends(authorize)):
    ensure_editable()
    p=validate_policy(body,actor=user['username'])
    rid='P-'+uuid.uuid4().hex[:12]
    with conn() as c:
        c.execute(insert_policy_sql(),policy_row(rid,p))
    revision(user['username'],'policy add')
    audit(user['username'],'policy_add',rid)
    return {'id':rid}


@app.put('/api/policies/{rid}')
def edit_policy(rid: str, body: PolicyIn, user=Depends(authorize)):
    ensure_editable()
    p=validate_policy(body,rid,actor=user['username'])
    with conn() as c:
        record={'id':rid,**p}
        assignments=','.join(k+'=?' for k in POLICY_FIELDS if k!='id')
        count=c.execute('UPDATE policies SET '+assignments+' WHERE id=?',
                        tuple(record[k] for k in POLICY_FIELDS if k!='id')+(rid,)).rowcount
    if not count:
        raise HTTPException(404,'Unknown policy')
    revision(user['username'],'policy edit')
    audit(user['username'],'policy_edit',rid)
    return {'ok':True}


@app.delete('/api/policies/{rid}')
def delete_policy(rid: str, user=Depends(authorize)):
    ensure_editable()
    with conn() as c:
        count=c.execute('DELETE FROM policies WHERE id=?',(rid,)).rowcount
    if not count:
        raise HTTPException(404,'Unknown policy')
    revision(user['username'],'policy delete')
    audit(user['username'],'policy_delete',rid)
    return {'ok':True}


def prepare():
    all_hosts={x['id']:x for x in hosts()}
    registered={x['id']:x for x in registry()}
    configured=list(all_hosts.values())
    if any(x['id'] not in registered for x in configured):
        raise ValueError('Unenrolled host detected')
    current=policies()
    candidate={ident:{'version':2,'host_ip':h['ip'],'host_ipv6':h.get('ipv6'),'rules':[]}
               for ident,h in registered.items()}
    for h in configured:
        if registered[h['id']]['ip']!=h['ip']:
            raise ValueError('Host enrollment IP changed: '+h['id'])
    for p in current:
        if not p['enabled']:
            continue
        a,b=all_hosts[p['src']],all_hosts[p['dst']]
        if not (a['enabled'] and b['enabled']):
            continue
        norm=normalized_policy(PolicyIn.model_validate(p),excluded=p['id'],check_duplicates=False)
        family=4 if norm['family']=='ipv4' else 6
        sa=registered[p['src']]['ip'] if family==4 else registered[p['src']].get('ipv6')
        da=registered[p['dst']]['ip'] if family==4 else registered[p['dst']].get('ipv6')
        if not sa or not da:
            raise ValueError('Missing enrolled IPv6 endpoint')
        source=parse_cidrs(norm['src_cidrs'],family,sa)
        destination=parse_cidrs(norm['dst_cidrs'],family,da)
        ports=port_ranges(norm['ports'],norm['port']) if p['proto'] in ('tcp','udp') else []
        for host_id,direction in ((a['id'],'output'),(b['id'],'input')):
            candidate[host_id]['rules'].append({
                'id':p['id'],'source':source,'destination':destination,
                'family':norm['family'],'proto':p['proto'],'ports':ports,
                'direction':direction,'action':norm['action'],
                'states':[v for v in norm['states'].split(',') if v],
                'log_drop':bool(norm['log_drop']),'icmp_type':norm['icmp_type'],
                'priority':norm['priority']})
    for c in candidate.values():
        c['rules'].sort(key=lambda v:(v['direction'],v['priority'],v['id']))
        if len(json.dumps(c,sort_keys=True).encode())>131072:
            raise ValueError('Candidate exceeds agent 128 KiB upload limit; narrow CIDR/port lists')
    material=json.dumps({'hosts':configured,'policies':current,'candidate':candidate},sort_keys=True)
    return candidate,hashlib.sha256(material.encode()).hexdigest()


def ssh(host, *command, input=None):
    cmd = ['/usr/bin/ssh','-F','/dev/null','-T','-i',str(SSH_KEY),
           '-o','BatchMode=yes','-o','IdentitiesOnly=yes',
           '-o','StrictHostKeyChecking=yes',
           '-o','UserKnownHostsFile='+str(KNOWN),
           '-o','ConnectTimeout=8', '-o','ConnectionAttempts=1',
           'agent_hbf@'+host['ip'], *command]
    p = subprocess.run(cmd, capture_output=True, text=True, input=input, timeout=35)
    if p.returncode:
        raise RuntimeError('%s: %s' % (host['id'], (p.stderr or p.stdout).strip()[:400]))
    return p.stdout.strip()


def agent(host, operation):
    if operation not in ('status','stage','arm','apply','verify','commit','rollback','quarantine-on','quarantine-off'):
        raise ValueError('Unsupported remote operation')
    return ssh(host, 'sudo','-n','/usr/local/sbin/hbf-alpha-agent',operation)


@app.get('/api/agents')
def get_agents(user=Depends(authorize)):
    result = []
    for h in hosts():
        try:
            state=json.loads(agent(h,'status'))
            result.append({**h,'reachable':True,**state})
        except (RuntimeError, ValueError, subprocess.SubprocessError) as e:
            result.append({**h,'reachable':False,'error':str(e)[:300]})
    return result


class QuarantineRequest(BaseModel):
    confirm: str


@app.post('/api/hosts/{hid}/quarantine')
def set_host_quarantine(hid: str, body: QuarantineRequest, user=Depends(authorize)):
    if body.confirm not in ('QUARANTINE', 'RELEASE'):
        raise HTTPException(422, 'Confirm QUARANTINE or RELEASE')
    entry = next((h for h in registry() if h['id'] == hid), None)
    managed = next((h for h in hosts() if h['id'] == hid and h['enabled']), None)
    if not entry or not managed:
        raise HTTPException(404, 'Host not enrolled or not enabled')
    if not LOCK.acquire(blocking=False):
        raise HTTPException(409, 'Deployment or quarantine operation is running')
    try:
        # An unresolved partial deploy must be reconciled BEFORE changing
        # quarantine state; otherwise operational state becomes ambiguous.
        with conn() as c:
            if c.execute("SELECT 1 FROM deployments WHERE state IN ('partial','running') LIMIT 1").fetchone():
                raise HTTPException(409, 'Resolve running/partial deployment first')
        state = json.loads(agent(entry, 'status'))
        if state.get('schema') != 3 or state.get('state') != 'CLEAN':
            raise HTTPException(409, 'Quarantine requires Alpha 1.3 agent and CLEAN transaction')
        desired = body.confirm == 'QUARANTINE'
        if bool(state.get('quarantined')) == desired and bool(state.get('quarantine_desired')) == desired:
            return {'ok': True, 'id': hid, 'quarantined': desired, 'result': 'ALREADY_SET'}
        operation = 'quarantine-on' if desired else 'quarantine-off'
        response = agent(entry, operation)
        verified = json.loads(agent(entry, 'status'))
        if bool(verified.get('quarantined')) != desired or bool(verified.get('quarantine_desired')) != desired:
            raise HTTPException(503, 'Agent quarantine status mismatch; check host console')
        audit(user['username'], 'quarantine_on' if desired else 'quarantine_off',
              hid + ': ' + response)
        return {'ok': True, 'id': hid, 'quarantined': desired, 'result': response}
    except (RuntimeError, ValueError, subprocess.SubprocessError) as e:
        audit(user['username'], 'quarantine_operation_error', hid + ': ' + str(e)[:250])
        raise HTTPException(503, 'Quarantine operation failed: ' + str(e)[:250])
    finally:
        LOCK.release()


@app.get('/api/export')
def export_config(user=Depends(authorize)):
    return {'schema':'hbf-alpha-2','exported':now(),'hosts':hosts(),'policies':policies()}


class ImportData(BaseModel):
    schema_id: str = Field(alias='schema')
    policies: list[dict]


@app.post('/api/import')
def import_config(body: ImportData,user=Depends(authorize)):
    ensure_editable()
    if body.schema_id not in ('hbf-alpha-1','hbf-alpha-2') or len(body.policies)>512:
        raise HTTPException(422,'Unsupported schema or too many policies')
    seen_ids=set();seen_matches=set();clean=[]
    for raw in body.policies:
        try:
            p=PolicyIn.model_validate(raw)
            rid=raw.get('id')
            if not isinstance(rid,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,48}',rid) or rid in seen_ids:
                raise ValueError('Invalid or duplicate policy ID')
            norm=normalized_policy(p,excluded=rid,check_duplicates=False)
            key=(norm['src'],norm['dst'],norm['proto'],norm['family'],norm['ports'],
                 norm['src_cidrs'],norm['dst_cidrs'],norm['states'],norm['icmp_type'],norm['priority'])
            if norm['enabled'] and key in seen_matches:
                raise ValueError('Duplicate active traffic match')
            if norm['enabled']:
                seen_matches.add(key)
            seen_ids.add(rid)
            clean.append(policy_row(rid,norm))
        except (ValueError,TypeError) as exc:
            raise HTTPException(422,str(exc))
        except Exception as exc:
            if isinstance(exc,HTTPException): raise
            raise HTTPException(422,'Invalid policy record')
    with conn() as c:
        c.execute('DELETE FROM policies')
        c.executemany(insert_policy_sql(),clean)
    revision(user['username'],'policy JSON import')
    audit(user['username'],'import',str(len(clean))+' policies')
    return {'ok':True,'count':len(clean),'note':'Imported to database, not applied to hosts'}




# YAML import/export is data-only. PREVIEW never modifies DB, and IMPORT is an
# atomic, explicitly confirmed transaction; neither executes a Deploy.
class YAMLRequest(BaseModel):
    text: str = Field(max_length=MAX_YAML_BYTES)
    mode: str = 'merge'  # merge: upsert by policy ID; replace: remove absent IDs


class YAMLImportRequest(YAMLRequest):
    fingerprint: str
    confirm: str


def yaml_current_rows():
    return policies()


def yaml_fingerprint(text: str, mode: str, current: list[dict]):
    payload = json.dumps({'text': text, 'mode': mode, 'policies': current},
                         sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def yaml_plan(text: str, mode: str, current: list[dict]):
    if mode not in ('merge', 'replace'):
        raise HTTPException(422, 'Mode must be merge or replace')
    try:
        inputs = parse_yaml(text)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    original = {p['id']: p for p in current}
    target = dict(original) if mode == 'merge' else {}
    for n, raw in enumerate(inputs, 1):
        try:
            p = PolicyIn.model_validate(raw)
            norm = normalized_policy(p, excluded=raw['id'],
                                     check_duplicates=False, audit_validation=False)
        except HTTPException as exc:
            raise HTTPException(exc.status_code, f'Rule #{n} ({raw["id"]}): {exc.detail}')
        except Exception as exc:
            from pydantic import ValidationError
            if isinstance(exc, ValidationError):
                raise HTTPException(422, f'Rule #{n} ({raw["id"]}): invalid fields: {str(exc)[:220]}')
            raise
        target[raw['id']] = {'id': raw['id'], **norm}
    if len(target) > 512:
        raise HTTPException(422, 'Result exceeds 512 policies; split or remove records')
    # Check all active rules together, not just against the old DB. This
    # prevents imports from silently creating conflicting same-priority rules.
    projected = list(target.values())
    for n, rec in enumerate(projected, 1):
        if not rec['enabled']:
            continue
        try:
            normalized_policy(PolicyIn.model_validate(rec), excluded=rec['id'],
                              check_duplicates=True, existing_records=projected,
                              audit_validation=False)
        except HTTPException as exc:
            raise HTTPException(422, f'Conflicting policy {rec["id"]}: {exc.detail}')
    added = []
    changed = []
    unchanged = []
    removed = []
    for rid, rec in target.items():
        if rid not in original:
            added.append(rid)
        elif rec == original[rid]:
            unchanged.append(rid)
        else:
            changed.append(rid)
    removed = sorted(set(original) - set(target))
    proposed = sorted(target.values(), key=lambda r: r['id'])
    return {
        'fingerprint': yaml_fingerprint(text, mode, current),
        'mode': mode,
        'counts': {'add': len(added), 'update': len(changed),
                   'unchanged': len(unchanged), 'remove': len(removed),
                   'total': len(proposed)},
        'changes': {'add': sorted(added), 'update': sorted(changed),
                    'unchanged': sorted(unchanged), 'remove': removed},
        'policies': proposed,
        'note': 'Database only. No firewall changes until an explicit Deploy.',
    }


@app.get('/api/yaml/export')
def yaml_export(user=Depends(authorize)):
    return {'filename': 'hbf-alpha-policies.yaml', 'yaml': export_yaml(policies())}


@app.post('/api/yaml/preview')
def yaml_preview(body: YAMLRequest, user=Depends(authorize)):
    ensure_editable()
    return yaml_plan(body.text, body.mode, yaml_current_rows())


@app.post('/api/yaml/import')
def yaml_import(body: YAMLImportRequest, user=Depends(authorize)):
    expected = 'IMPORT_YAML' if body.mode == 'merge' else 'REPLACE_POLICIES'
    if body.confirm != expected:
        raise HTTPException(422, 'Explicit confirmation required: ' + expected)
    if not LOCK.acquire(blocking=False):
        raise HTTPException(409, 'Deployment/operation in progress')
    try:
        ensure_editable()
        # A deferred writer lock serializes policy mutation with other writes;
        # compare fingerprint after acquiring it to detect stale previews.
        with conn() as c:
            c.execute('BEGIN IMMEDIATE')
            if c.execute("SELECT 1 FROM deployments WHERE state IN ('running','partial') LIMIT 1").fetchone():
                raise HTTPException(409, 'Resolve active/partial deployment first')
            current = [dict(r) for r in c.execute('SELECT * FROM policies ORDER BY id')]
            fingerprint = yaml_fingerprint(body.text, body.mode, current)
            if not hmac.compare_digest(fingerprint, body.fingerprint):
                raise HTTPException(409, 'YAML preview is stale. Preview again.')
            plan = yaml_plan(body.text, body.mode, current)
            c.execute('DELETE FROM policies')
            c.executemany(insert_policy_sql(),
                          [policy_row(r['id'], r) for r in plan['policies']])
            snapshot = json.dumps({
                'hosts': [dict(h) for h in c.execute('SELECT * FROM hosts ORDER BY id')],
                'policies': [dict(p) for p in c.execute('SELECT * FROM policies ORDER BY id')],
            }, sort_keys=True)
            c.execute('INSERT INTO revisions(created,actor,reason,snapshot) VALUES (?,?,?,?)',
                      (now(), user['username'], 'YAML '+body.mode+' import', snapshot))
            c.execute('INSERT INTO audit(created,actor,action,details) VALUES (?,?,?,?)',
                      (now(), user['username'], 'yaml_import',
                       body.mode+' '+json.dumps(plan['counts'], sort_keys=True)))
        return {'ok': True, 'counts': plan['counts'], 'mode': body.mode,
                'note': 'Policies saved to database; separately review Plan/Diff and Deploy.'}
    finally:
        LOCK.release()

@app.get('/api/preview')
def preview(user=Depends(authorize)):
    try:
        candidates,fingerprint = prepare()
    except (ValueError, KeyError) as e:
        raise HTTPException(422,str(e))
    return {'fingerprint':fingerprint,'targets':[
        {'id':hid,'host_ip':v['host_ip'],'rule_count':len(v['rules']),'rules':v['rules']}
        for hid,v in candidates.items()], 'note':'ACCEPT/DROP/REJECT with default accept; ACCEPT only overrides later rules in HBF chain. No cross-host atomic commit.'}


def plan_diff(candidates: dict):
    with conn() as c:
        baselines={r['host_id']:dict(r) for r in c.execute('SELECT * FROM applied_state')}
    result=[]
    for hid,candidate in candidates.items():
        old=baselines.get(hid)
        new_rules={json.dumps(r,sort_keys=True):r for r in candidate['rules']}
        if not old:
            result.append({'id':hid,'baseline_known':False,'add':[], 'remove':[],
                           'unchanged':[], 'current_count':None,'new_count':len(new_rules),
                           'note':'Нет подтверждённого baseline; сравнение неизвестно'})
            continue
        prior=json.loads(old['candidate'])
        old_rules={json.dumps(r,sort_keys=True):r for r in prior['rules']}
        result.append({'id':hid,'baseline_known':True,
                       'add':[new_rules[x] for x in sorted(new_rules.keys()-old_rules.keys())],
                       'remove':[old_rules[x] for x in sorted(old_rules.keys()-new_rules.keys())],
                       'unchanged':[new_rules[x] for x in sorted(new_rules.keys()&old_rules.keys())],
                       'current_count':len(old_rules),'new_count':len(new_rules),
                       'updated':old['updated'],'deployment_id':old['deployment_id']})
    return result


@app.get('/api/plan-diff')
def get_plan_diff(user=Depends(authorize)):
    try:
        candidates,fp=prepare()
    except (ValueError, KeyError) as exc:
        raise HTTPException(422,str(exc))
    return {'fingerprint':fp,'targets':plan_diff(candidates),
            'note':'Diff относительно последнего подтверждённого успешного COMMIT. Не является измерением live nftables.'}


@app.get('/api/preflight')
def preflight(user=Depends(authorize)):
    blockers=[]
    try:
        candidates,fingerprint=prepare()
    except (ValueError, KeyError) as e:
        return {'ready':False,'blockers':[str(e)]}
    for h in registry():
        try:
            info=json.loads(agent(h,'status'))
            if info['state'] != 'CLEAN':
                blockers.append(h['id']+': transaction pending')
            if info.get('schema') != 3:
                blockers.append(h['id']+': Alpha 1.3 agent not installed (schema v3 required)')
            if info.get('quarantined') or info.get('quarantine_desired'):
                blockers.append(h['id']+': QUARANTINED; release quarantine before Deploy')
        except Exception as e:
            blockers.append(h['id']+': '+str(e)[:180])
    with conn() as c:
        stuck=c.execute("SELECT id FROM deployments WHERE state IN ('running','partial') LIMIT 1").fetchone()
    if stuck:
        blockers.append('Unreconciled job: '+stuck['id'])
    return {'ready':not blockers,'blockers':blockers,'fingerprint':fingerprint,
            'hosts':len(candidates),'note':'TCP/UDP ports 22,8088 protected; no strict cross-host atomicity'}


def log(job_id, message, state=None):
    with conn() as c:
        record=c.execute('SELECT logs,state FROM deployments WHERE id=?',(job_id,)).fetchone()
        if not record:
            return
        logs=json.loads(record['logs'])
        logs.append({'at':now(),'message':str(message)[:600]})
        c.execute('UPDATE deployments SET logs=?,state=?,updated=? WHERE id=?',
                  (json.dumps(logs[-250:]), state or record['state'], now(),job_id))


def worker(job_id,candidates):
    enrolled={x['id']:x for x in registry()}
    # Never take arbitrary IPs from the browser.
    targets=[enrolled[h] for h in candidates]
    armed=[]
    committed=[]
    try:
        for h in targets:
            log(job_id,'UPLOAD '+h['id'])
            payload=json.dumps(candidates[h['id']],sort_keys=True)
            ssh(h,'/usr/local/bin/hbf-alpha-upload',input=payload)
        for h in targets:
            log(job_id,'STAGE '+h['id'])
            agent(h,'stage')
        for h in targets:
            log(job_id,'ARM '+h['id'])
            agent(h,'arm')
            armed.append(h)
        for h in targets:
            log(job_id,'APPLY '+h['id'])
            agent(h,'apply')
        for h in targets:
            log(job_id,'VERIFY '+h['id'])
            agent(h,'verify')
        for h in targets:
            log(job_id,'COMMIT '+h['id'])
            agent(h,'commit')
            committed.append(h)
        # Persist comparison baseline only after every host confirmed COMMIT.
        # A partial or crashed deployment must not be treated as an applied baseline.
        with conn() as c:
            for hid, candidate in candidates.items():
                c.execute('''INSERT INTO applied_state(host_id,candidate,updated,deployment_id)
                             VALUES (?,?,?,?)
                             ON CONFLICT(host_id) DO UPDATE SET
                             candidate=excluded.candidate,updated=excluded.updated,
                             deployment_id=excluded.deployment_id''',
                          (hid,json.dumps(candidate,sort_keys=True),now(),job_id))
        log(job_id,'COMMITTED on all targets','success')
        audit('system','deploy_success',job_id)
    except Exception as e:
        log(job_id,'ERROR: '+str(e))
        for h in reversed(armed):
            if h in committed:
                continue
            try:
                agent(h,'rollback')
                log(job_id,'ROLLBACK '+h['id']+' OK')
            except Exception as err:
                log(job_id,'ROLLBACK '+h['id']+': '+str(err)[:180])
        state='partial' if committed else 'failed'
        log(job_id,'Deployment '+state.upper()+'. Check all host states; watchdog remains on pending nodes.',state)
        audit('system','deploy_'+state,job_id)
    finally:
        LOCK.release()


class DeployRequest(BaseModel):
    fingerprint: str
    confirm: str


@app.post('/api/deploy')
def deploy(body: DeployRequest, user=Depends(authorize)):
    if body.confirm != 'DEPLOY':
        raise HTTPException(422,'Type DEPLOY to confirm')
    if not LOCK.acquire(blocking=False):
        raise HTTPException(409,'Another deployment is running')
    try:
        with conn() as c:
            if c.execute("SELECT 1 FROM deployments WHERE state='partial' LIMIT 1").fetchone():
                raise HTTPException(409,'Unreconciled partial deployment. Manual intervention required.')
        candidates,fp=prepare()
        if not hmac.compare_digest(body.fingerprint,fp):
            raise HTTPException(409,'Policies changed after preview')
        # Preflight remote status again before accepting any live operation.
        for h in registry():
            state=json.loads(agent(h,'status'))
            if state['state']!='CLEAN':
                raise HTTPException(409,h['id']+': pending transaction')
            if state.get('schema')!=3:
                raise HTTPException(409,h['id']+': Alpha 1.3 agent schema v3 required')
            if state.get('quarantined') or state.get('quarantine_desired'):
                raise HTTPException(409,h['id']+': quarantine active; release before Deploy')
        job='D-'+uuid.uuid4().hex[:12]
        with conn() as c:
            c.execute('INSERT INTO deployments VALUES (?,?,?,?,?,?)',
                      (job,now(),now(),'running',fp,'[]'))
        audit(user['username'],'deploy_start',job)
        thread=threading.Thread(target=worker,args=(job,candidates),daemon=True)
        thread.start()
        return {'job_id':job,'state':'running'}
    except Exception:
        LOCK.release()
        raise


@app.get('/api/deployments')
def deployments(user=Depends(authorize)):
    with conn() as c:
        return [dict(x) for x in c.execute('SELECT * FROM deployments ORDER BY created DESC LIMIT 30')]


@app.get('/api/deployments/{job_id}')
def get_deployment(job_id: str, user=Depends(authorize)):
    with conn() as c:
        job=c.execute('SELECT * FROM deployments WHERE id=?',(job_id,)).fetchone()
    if not job:
        raise HTTPException(404,'Unknown job')
    return {**dict(job),'logs':json.loads(job['logs'])}


class ReconcileRequest(BaseModel):
    confirm: str


@app.post('/api/reconcile/{job_id}')
def reconcile(job_id: str, body: ReconcileRequest, user=Depends(authorize)):
    if body.confirm != 'ACK_PARTIAL':
        raise HTTPException(422,'Type ACK_PARTIAL to reconcile')
    with conn() as c:
        row=c.execute('SELECT state FROM deployments WHERE id=?',(job_id,)).fetchone()
    if not row or row['state'] != 'partial':
        raise HTTPException(409,'Job is not an unresolved partial deployment')
    for h in registry():
        response=json.loads(agent(h,'status'))
        if response['state']!='CLEAN':
            raise HTTPException(409,h['id']+' has pending transaction')
    with conn() as c:
        c.execute("UPDATE deployments SET state='reconciled',updated=? WHERE id=? AND state='partial'",(now(),job_id))
    audit(user['username'],'partial_acknowledged',job_id)
    log(job_id,'Operator acknowledged CLEAN transaction states. Live policies may differ; perform fresh Deploy.')
    return {'ok':True,'note':'Acknowledged, not restored: immediately review and redeploy intended policy.'}


@app.get('/api/revisions')
def revisions(user=Depends(authorize)):
    with conn() as c:
        return [dict(x) for x in c.execute(
            'SELECT id,created,actor,reason FROM revisions ORDER BY id DESC LIMIT 50')]


@app.post('/api/revisions/{rev_id}/restore')
def restore_revision(rev_id: int, user=Depends(authorize)):
    ensure_editable()
    with conn() as c:
        row=c.execute('SELECT snapshot FROM revisions WHERE id=?',(rev_id,)).fetchone()
    if not row:
        raise HTTPException(404,'Unknown revision')
    data=json.loads(row['snapshot'])
    available={h['id'] for h in hosts()}
    if any(p['src'] not in available or p['dst'] not in available for p in data['policies']):
        raise HTTPException(409,'Revision references missing host; restore hosts first')
    clean=[]
    for raw in data['policies']:
        p=PolicyIn.model_validate(raw)
        norm=normalized_policy(p,excluded=raw['id'],check_duplicates=False)
        clean.append(policy_row(raw['id'],norm))
    with conn() as c:
        c.execute('DELETE FROM policies')
        c.executemany(insert_policy_sql(),clean)
    revision(user['username'],'restore policies from revision '+str(rev_id))
    audit(user['username'],'revision_restore',str(rev_id))
    return {'ok':True,'note':'Policies restored in database. Run preview and Deploy to apply.'}


@app.get('/api/audit')
def audit_history(user=Depends(authorize)):
    with conn() as c:
        return [dict(x) for x in c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 150')]


if __name__ == '__main__':
    if len(sys.argv)==2 and sys.argv[1]=='init-admin':
        create_admin()
    else:
        sys.exit('Usage: app.py init-admin')
