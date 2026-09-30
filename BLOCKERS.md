# Runtime status — 2026-09-30

The virtiofs Unix-socket startup blocker is resolved. The host supervisor now
connects through generation-pinned TLS to a per-sandbox TCP port published on
127.0.0.1. The guest reads bootstrap inputs from a read-only share and copies
them into its private runtime directory before launching the boundary.

The entrypoint installs default-deny IPv4/IPv6 firewall rules and the policy
DNS resolver before dropping all capabilities. Supervisor authentication stays
on the host. HTTPS interception uses a private host CA directory and the
upstream guest trust-material installation path.

Verified on an Apple Silicon Mac with macOS 27 and Apple Container 1.3.1:

- Sandbox reaches Ready and executes commands as uid/gid 1000.
- Effective capabilities are empty and no_new_privs is set.
- Policy-approved HTTPS to api.github.com succeeds.
- Direct-IP outbound traffic and an unlisted HTTPS host are blocked.
- Multiple sandboxes use separate published ports.
- The 35 driver tests pass, including transport and read-only mount assertions.

Remaining limitations: workspace data uses Apple Container volumes, not a live
host-directory mount. Recovery of existing sandboxes after a driver restart
and refresh of launch credentials on stop/start still need dedicated work;
the installer smoke test currently verifies fresh sandbox creation and removal.
