# VeilGraph secure-online deployment profile

VeilGraph has two deployment modes:

- **Competition/offline:** bind to `127.0.0.1`, no external model API calls.
- **Secure-online:** HTTPS is mandatory, bearer authentication is mandatory, and forwarded HTTPS is trusted only from explicitly configured proxy networks.

The automated acceptance `scripts/run_secure_online_acceptance.py` starts the real FastAPI/Uvicorn application over a TLS socket with an ephemeral local certificate, proves unauthenticated requests are rejected, proves authenticated requests are accepted, and records evidence under `competition/phase3/`.

For an organisational deployment, terminate public TLS either directly at Uvicorn with organisation-managed certificates or at a trusted reverse proxy. If proxy termination is used, configure `VEILGRAPH_TRUST_PROXY_HEADERS=true` and explicit `VEILGRAPH_TRUSTED_PROXY_NETWORKS`; never trust forwarded headers from arbitrary clients.
