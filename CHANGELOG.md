# HBF Alpha 1.4 R2

- Controller-only YAML policy import/export, with legacy format (`id`, `source`, `destination`, `protocol`, `destination_port`, `description`).
- Dry-run preview plus explicit merge-by-ID or replace-all confirmation; stale preview rejects; atomic import transaction with revision and audit.
- Strict SafeLoader, protected SSH/22 and UI/8088, known/enrolled host validation, priority conflict checks, file/rule count limits.
- Web Console import/export actions, corrected example YAML, focused upgrade playbook. No live agent changes or automatic Deploy.
- Regression tests for YAML API, injection/aliases/duplicate keys, JSON export compatibility, partial Deploy protection.
- Based on Alpha 1.3 R2; original quarantine, rollback and IPv4/IPv6 rules unchanged.
