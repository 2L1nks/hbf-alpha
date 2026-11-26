"""Pure, deterministic read-only policy topology model for HBF Alpha 1.2 R2.

Edges represent declared policies (ACCEPT/DROP/REJECT), not observed physical links or allowed
network traffic. There is one directed edge per source/destination pair, with
all matching policies aggregated; UI further coalesces group-to-group edges.
"""
from __future__ import annotations

from collections import defaultdict


def build_topology(hosts: list[dict], policies: list[dict]) -> dict:
    ordered_hosts = sorted((dict(h) for h in hosts), key=lambda h: h['id'])
    node_by_id = {h['id']: h for h in ordered_hosts}
    groups = defaultdict(list)
    for h in ordered_hosts:
        groups[h.get('grp') or 'Без группы'].append(h['id'])
    edges = defaultdict(list)
    for raw in policies:
        p = dict(raw)
        a, b = p.get('src'), p.get('dst')
        if a not in node_by_id or b not in node_by_id:
            continue
        edges[a,b].append(p)
    directed = []
    for (src,dst), rules in sorted(edges.items()):
        ordered = sorted(rules, key=lambda p:p['id'])
        active = [r for r in ordered if r['enabled'] and node_by_id[src]['enabled'] and node_by_id[dst]['enabled']]
        directed.append({'id':src+'→'+dst,'source':src,'target':dst,
                         'source_group':node_by_id[src].get('grp') or 'Без группы',
                         'target_group':node_by_id[dst].get('grp') or 'Без группы',
                         'policy_count':len(ordered),'active_count':len(active),
                         'disabled_count':len(ordered)-len(active),
                         'protocols':sorted({r['proto'] for r in ordered}),
                         'ports':sorted({str(r.get('ports') or r.get('port')) for r in ordered}),
                         'rules':ordered})
    return {'version':'1.2','kind':'declared_hbf_policies',
            'note':'Связи — объявленные политики HBF, а не обнаруженные физические или разрешённые сетевые соединения.',
            'nodes':ordered_hosts,
            'groups':[{'id':k,'label':k,'host_ids':v,'host_count':len(v)} for k,v in sorted(groups.items())],
            'edges':directed,
            'stats':{'hosts':len(ordered_hosts),'groups':len(groups),'directed_pairs':len(directed),
                     'policies':sum(len(e['rules']) for e in directed),
                     'active_policies':sum(e['active_count'] for e in directed)}}


def graph_stats(graph: dict) -> dict:
    """Extract summary for UI cards without leaking any agent credentials."""
    return dict(graph['stats'])
