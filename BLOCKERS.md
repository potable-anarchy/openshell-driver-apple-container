# Blockers — status as of 2026-09-29 22:30 PDT

## Architecture decision needed (root cause of B1)

Main's supervisor/workload boundary model assumes: supervisor and boundary processes
can share /dev, netns, and a sandbox-internal UDS channel; boundary probes its own
network virtualization + Landlock and then launches the dropped workload.

Apple Container (one VM per container) cannot:
- Share a Linux network namespace between containers (each is its own VM).
- Expose supervisor-only privileges to one INSIDE-the-VM process while another runs
  unprivileged — they share the VM's net + user namespace.
- Expose host-mounted unix sockets both directions cleanly in podman's pattern.

Consequences for our launch path:
- Boundary probes (Landlock ABI v3, socket virtualization, DNS-relay bind at
  127.0.0.53:53) require CAP_NET_BIND_SERVICE and full caps — but we drop these
  via launch-capability-free BEFORE probes run.
- Reversing the order (launch-capability-free LAST) puts us right back at the
  "boundary runs as root" anti-pattern.
- Putting supervisor INSIDE the VM (current entrypoint) makes probes succeed as
  root but then drops them — so qualification kicks back to probes-can't-run.
- Putting supervisor OUTSIDE the VM (host, VM driver pattern) requires supervisor
  to reach the boundary over a UDS that the hypervisor exposes. Trybox's virtiofs
  share does pass unix sockets host⇄guest (verified with socat bind under Debian).
  That's OUR viable pattern, but it needs:
    - Supervisor process hosted by the DRIVER (not the guest)
    - Driver stages the channel dir so the guest's boundary binds
      /.openshell/channel/sandbox/sandbox.sock; supervisor on host dials the
      host-side same path.

## What worked

- Host/Guest unix sockets over virtiofs: VERIFIED
- Per-sandbox staging w/ auth.json + backend-descriptor.json + bootstrap.json:
  VERIFIED (all files written, correct shape, supervisor accepts the auth bundle
  when the runtime_generation matches)
- Trybox-entrypoint as PID 1: spawns launch-capability-free, propagates exit.
- Driver UDS+gRPC domain: VERIFIED end-to-end.

## Still needed (B1 strict)

1. Move supervisor spawn out of `trybox-entrypoint` into the **driver**, like
   openshell-driver-vm's spawn_host_supervisor. Driver runs openshell-supervisor
   (macOS arm64) on the host, points it at the host-side channel path; supervisor
   then dials the boundary inside the VM.
2. Channel mount becomes **read-write** for boundary consumption (one-use).
3. Outer-fence guarantees need actual enforcement: currently asserted only.
4. Supervisor-binary preflight: validate host-bin dir contains openshell-supervisor
   before launching.

## Bypass decision

Until (1) lands, sandbox create ends at "ContainerStopped" inside the VM error
phase. No user-facing e2e completion is possible without the supervisor spawn
changes above; trybox "my idea" gets past dir create + sandbox provisioning and
then fails during sandbox boot.
