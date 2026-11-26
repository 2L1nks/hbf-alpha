# Security notes for HBF Alpha 1.4 R2

This repository is a **laboratory build**, not a production-ready firewall management platform. Keep it **private** until a dedicated security and deployment review is complete.

- Never commit SSH private keys, live inventories, credentials, controller databases, sessions, deployment logs, or nftables runtime dumps.
- `bootstrap/inventory.yml` is a **laboratory example** with RFC1918 addresses (`192.168.100.10` and `192.168.100.20`). Maintain production inventories separately; do not commit them.
- `examples/legacy-corrected.yaml` contains an **enabled** TCP/8080 DROP policy for lab use. Importing it changes the policy database, and a later explicit Deploy may block connectivity.
- HBF protects management ports TCP/22 and TCP/8088 by design; do not bypass these constraints.
- YAML import creates/updates stored policies and **does not automatically Deploy** them. Review Plan/Diff before any deployment.
- A quarantine still allows controller-origin SSH/TCP22. It is not physical/L2 isolation.
- The current web console uses a lab HTTP endpoint (`secure=False` on session cookies). Do not expose it directly on public or untrusted networks.
- Restore and PARTIAL transaction handling must be validated on the target environment before wider deployment.

No public license is included. Select and review a license separately if public distribution is later desired.
