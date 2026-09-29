# Blockers — status as of 2026-09-29 23:30 PDT

## Apple Container / virtiofs does not permit Unix socket bind() to the kind
the boundary requires (EINVAL on `bind()` after fresh socket creation via
`socat -u UNIX-LISTEN`), and cross-UID `unlink(2)` of socket inodes through
the same share is rejected with EOPERATIONNOTSUPP.

Verified by isolated socat runs inside a sandbox container:

    container run --rm -v HOST_PATH:/.openshell/channel:rw IMAGE \
      socat -u UNIX-LISTEN:/.openshell/channel/sandbox/test.sock,fork NOOP

    → successfully creates a NEW socket
    → any subsequent bind on the SAME path fails with EINVAL
    → remove_file(socket) returns "Operation not supported"

The upstream boundary listener (`openshell-sandbox/src/boundary_server.rs`)
uses `remove_owned_stale_control_socket()` (`unlink(2)` then `UnixListener::bind`)
on the channel mount. On virtiofs both halves of that pattern break:
  - The host-side passenger uid (typically 501) is what virtiofs reports for
    staged files, while the boundary runs as uid 1000 → ownership guard
    refuses the unlink.
  - Even with ownership repaired, the kernel-side VFS layer for virtiofs
    refuses the actual `bind()` syscall on the share with EINVAL.

## Implication

`openshell-sandbox` (upstream) cannot run its boundary control listener on a
virtiofs channel mount. This is a real upstream constraint for any external
driver on macOS-arm64 that uses Apple's Shared Directory sharing mode. All
three workaround classes:

  A. **Move the channel off virtiofs** (chosen):
     use a tmpfs in the guest for the runtime channel; supervisor on the
     host dials the boundary over TLS TCP via `--publish`. Mirrors what the
     upstream VM driver does. Requires changing SandboxTransport::Unix →
     SandboxTransport::TlsTcp, BoundaryListener::Unix →
     BoundaryListener::TlsTcp, and adding `--publish` to the Apple CLI args.

  B. **Build a patched openshell-sandbox** locally and ship it with trybox:
     replace the boundary listener with a virtiofs-safe implementation.
     Diverges from stock upstream which is what trybox has been committed to
     (out-of-tree ≥ in-tree). Falls back into the same maintenance burden the
     original NVIDIA PR #1888 carried; undesirable.

  C. **Open an upstream issue with NVIDIA**: ask for either a transport
     alternative or a podman-style shared-fs contract for the boundary
     channel. Long lead time; does not unblock trybox.

## Current state of the repo (as of this commit)

- Driver spawns openshell-supervisor on the macOS host per sandbox ✓
- Driver launches an Apple container per sandbox with the entrypoint ✓
- Entrypoint runs `openshell-sandbox launch-capability-free` (drops to uid/gid 1000) ✓
- Boundary process STARTS (uid=1000 via launch-capability-free) ✓
- Entrypoint's `write_ctl_tweak` re-binds /proc/sys/net + writes
  `ip_unprivileged_port_start=0` via SYS_ADMIN cap ✓ (matches podman
  `--sysctl net.ipv4.ip_unprivileged_port_start=0`)
- Boundary's `bind boundary control listener` fails: EINVAL ✗
- Host supervisor has nothing to dial; sandbox never reaches Ready

## Next step (chosen): Track A — TlsTcp transport

1. driver.rs: use `SandboxTransport::TlsTcp { authority, addresses }`
   - authority = `host.container.internal:17672` (Apple VM default gateway)
   - addresses = `[127.0.0.1:17672]` (fallback)
2. driver.rs: `BoundaryListener::TlsTcp { address: 0.0.0.0:17672, tls: ... }`
3. driver.rs: `--publish 127.0.0.1:17672:17672` on the Apple container invocation
   so the gateway host can dial the guest boundary listener
4. STAGING_LAYOUT.md updated: channel mount is input-only (bootstrap.json
   reads once) or dropped entirely — the boundary only needs the TLS cert + key
   + the bootstrap, all of which are static-read inputs.
5. Image `local/trybox-sandbox`: `EXPOSE 17672` and the TLS cert/key copied
   in via volume or re-baked at image build time (choose at implementation).

E2E verification: `openshell sandbox create --name smoke --from local/trybox-sandbox:latest -- echo hello-from-sandbox` must reach `Ready`.
