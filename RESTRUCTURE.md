# Apple Container driver architecture (current)

## Actors per sandbox

1. **Host supervisor** — `openshell-supervisor` (Mach-O arm64), spawned by the driver as a
   host process. Talks to the boundary over the sandbox channel's Unix socket
   (virtiofs-backed, host-visible path). Has its own mTLS + JWT material to reach the
   gateway. Owns the egress boundary.

2. **Guest boundary** — `openshell-sandbox` (Linux aarch64 musl), runs inside Apple
   Container. Entrypoint is `trybox-entrypoint` (also Linux musl) which:
     1. chowns `SANDBOX_WORKDIR` to uid 1000 (CAP_CHOWN available pre-drop)
     2. spawns `openshell-sandbox launch-capability-free 1000 1000 /bootstrap.json` (drops caps + uid)
     3. boundary re-qualifies (Landlock/socket probes now succeed because NS setup happens pre-drop)
     4. boundary binds `/.openshell/channel/sandbox/sandbox.sock` and waits for supervisor attach.

## Driver responsibilities (host-side)

- Stage per-sandbox staging dir under `~/.local/state/openshell/apple-container-secrets/<ns>/<id>/`:
    - `supervisor/auth.json` (gateway's SupervisorAuthBundle)
    - `supervisor/backend-descriptor.json` (SandboxRuntimeDescriptor for boundary)
    - `channel/sandbox/bootstrap.json` (BoundaryConfig, one-use)
    - `channel/sandbox/server.crt` + `server.key` (TLS material for boundary listener)
- Spawn supervisor with the VM-driver pattern (kill-on-drop, stdout/err to sandbox logs).
- Spawn Apple Container with:
    - entrypoint /opt/openshell/bin/trybox-entrypoint
    - mounts:
      - supervisor bin dir (Linux binaries inside VM) readonly at /opt/openshell/bin
      - channel dir (host→guest virtiofs, READ-WRITE so boundary can consume bootstrap + bind socket) at /.openshell/channel
      - sandbox workspace volume mounted at SANDBOX_WORKDIR
- Watch processes; teardown on either exit.

## Transport

- Boundary listens on a Unix socket at `/.openshell/channel/sandbox/sandbox.sock` INSIDE the guest.
- virtiofs mounts this on the host as
  `~/.local/state/openshell/apple-container-secrets/<ns>/<id>/channel/sandbox/sandbox.sock`.
- Supervisor (host) connects to the host-side path.

## Known limits

- One Apple VM per sandbox. Supervisor + boundary cannot share a Linux namespace but they
  share the UDS channel via virtiofs.
- Workload egress is only over the boundary's UDS relay; the supervisor enforces policies.
- trybox-entrypoint owns the guest PID 1 lifecycle.
