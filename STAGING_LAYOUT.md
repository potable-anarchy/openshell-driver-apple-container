# Staging layout

Private host root:
`$XDG_STATE_HOME/openshell/apple-container-secrets/<namespace>/<sandbox-id>/`

- `supervisor/auth.json`: gateway-issued supervisor authentication; host only.
- `supervisor/backend-descriptor.json`: generation-pinned TLS client descriptor
  pointing to the loopback-published boundary port; host only.
- `channel/sandbox/{bootstrap.json,server.crt,server.key}`: mounted read-only at
  `/.openshell/channel/sandbox` and copied to `/run/trybox` in the guest.
- `proxy-tls/`: host supervisor's HTTPS policy-interception certificate material.
- `logs/`: host supervisor stdout/stderr.

The guest bootstrap uses `BoundaryListener::TlsTcp` on `0.0.0.0:17672` and TLS
files in `/run/trybox`. The driver uses a distinct loopback host port for each VM.
The upstream boundary installs public trust material in
`/run/openshell-supervisor-ca`, prepared by the entrypoint with mode 0755 and
ownership 1000:1000. It never receives the host gateway's authentication bundle.
