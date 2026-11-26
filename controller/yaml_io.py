"""Strict, data-only YAML policy interchange for HBF Alpha 1.4.

No object construction, aliases, duplicate keys, or implicit code execution.
Parsing is separate from database mutations; caller validates each rule via the
existing HBF policy validator and requires explicit confirmation before import.
"""
from __future__ import annotations

import json
import re

import yaml

MAX_YAML_BYTES = 1_048_576
MAX_YAML_POLICIES = 512


class StrictPolicyLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        event = self.peek_event()
        if isinstance(event, yaml.AliasEvent) or getattr(event, 'anchor', None):
            raise ValueError('YAML aliases/anchors are not allowed')
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ValueError('YAML mapping keys must be strings')
            if key in result:
                raise ValueError('Duplicate YAML key: ' + key[:70])
            result[key] = self.construct_object(value_node, deep=deep)
        return result


ALIASES = {
    'source': 'src', 'destination': 'dst', 'protocol': 'proto',
    'destination_port': 'port', 'description': 'note',
}
ALLOWED = frozenset({
    'id', 'name', 'src', 'dst', 'proto', 'port', 'ports', 'family',
    'action', 'enabled', 'priority', 'states', 'src_cidrs', 'dst_cidrs',
    'icmp_type', 'log_drop', 'note', 'tags', 'owner', 'ticket',
    *ALIASES,
})
STRING_FIELDS = frozenset({
    'id', 'name', 'src', 'dst', 'proto', 'family', 'action',
    'icmp_type', 'note', 'tags', 'owner', 'ticket',
})
LIST_FIELDS = frozenset({'ports', 'states', 'src_cidrs', 'dst_cidrs'})


def _joined(value, key):
    if isinstance(value, list):
        if not value:
            return ''
        if not all(isinstance(item, (str, int)) and not isinstance(item, bool)
                   for item in value):
            raise ValueError(key + ': use strings/numbers in lists')
        return ','.join(str(item) for item in value)
    if isinstance(value, str):
        return value
    if key == 'ports' and type(value) is int:
        return str(value)
    raise ValueError(key + ': expected a string or a list')


def parse_yaml(text: str) -> list[dict]:
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_YAML_BYTES:
        raise ValueError('YAML file exceeds 1 MiB or is not text')
    if '\x00' in text:
        raise ValueError('Invalid NUL in YAML')
    try:
        root = yaml.load(text, Loader=StrictPolicyLoader)
    except yaml.YAMLError as exc:
        raise ValueError('Invalid YAML syntax: ' + str(exc)[:230]) from exc
    if not isinstance(root, dict) or set(root) != {'version', 'policies'}:
        raise ValueError('YAML root must contain exactly version and policies')
    if type(root['version']) is not int or root['version'] != 1:
        raise ValueError('YAML policy document requires version: 1')
    entries = root['policies']
    if not isinstance(entries, list) or len(entries) > MAX_YAML_POLICIES:
        raise ValueError('YAML policies must be a list of at most 512 rules')
    records = []
    seen_ids = set()
    for n, record in enumerate(entries, 1):
        if not isinstance(record, dict):
            raise ValueError(f'Rule #{n}: expected mapping')
        unknown = set(record) - ALLOWED
        if unknown:
            raise ValueError(f'Rule #{n}: unknown fields: ' + ', '.join(sorted(unknown)))
        transformed = dict(record)
        for alias, canonical in ALIASES.items():
            if alias in transformed:
                if canonical in transformed:
                    raise ValueError(f'Rule #{n}: do not specify both {alias} and {canonical}')
                transformed[canonical] = transformed.pop(alias)
        rid = transformed.get('id')
        if not isinstance(rid, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', rid):
            raise ValueError(f'Rule #{n}: id is required (letters/numbers/_/-; up to 48)')
        if rid in seen_ids:
            raise ValueError(f'Rule #{n}: duplicate id {rid}')
        seen_ids.add(rid)
        # Old examples have description but no name. Keep both: stable ID as
        # short name and description as human-readable note.
        transformed.setdefault('name', rid)
        for key in STRING_FIELDS & transformed.keys():
            if not isinstance(transformed[key], str):
                raise ValueError(f'Rule #{n}: {key} must be a string')
        for key in LIST_FIELDS & transformed.keys():
            transformed[key] = _joined(transformed[key], key)
        if 'port' in transformed:
            v = transformed['port']
            if type(v) is int:
                pass
            elif isinstance(v, str) and re.fullmatch(r'[0-9]{1,5}', v):
                transformed['port'] = int(v)
            else:
                raise ValueError(f'Rule #{n}: destination_port/port must be one integer')
        for key in ('enabled', 'log_drop'):
            if key in transformed and type(transformed[key]) is not bool:
                raise ValueError(f'Rule #{n}: {key} must be true or false')
        if 'priority' in transformed and type(transformed['priority']) is not int:
            raise ValueError(f'Rule #{n}: priority must be an integer')
        transformed.setdefault('enabled', False)  # fail safe if absent
        records.append(transformed)
    return records


def export_yaml(rows: list[dict]) -> str:
    records = []
    for r in rows:
        record = {
            'id': r['id'],
            'name': r['name'],
            'description': r['note'],
            'enabled': bool(r['enabled']),
            'source': r['src'],
            'destination': r['dst'],
            'family': r['family'],
            'protocol': r['proto'],
            'action': r['action'],
            'priority': int(r['priority']),
        }
        if r['proto'] in ('tcp', 'udp'):
            record['ports'] = r['ports'] or str(r['port'])
        else:
            record['icmp_type'] = r['icmp_type']
        for key in ('states', 'src_cidrs', 'dst_cidrs', 'tags', 'owner', 'ticket'):
            if r[key]:
                record[key] = r[key]
        if r['log_drop']:
            record['log_drop'] = True
        records.append(record)
    return yaml.safe_dump({'version': 1, 'policies': records},
                          allow_unicode=True, sort_keys=False, default_flow_style=False)
