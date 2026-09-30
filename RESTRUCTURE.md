# Apple Container driver architecture

Each sandbox has a macOS host supervisor and a Linux boundary inside its own
Apple Container VM. The driver uses upstream OpenShell's authenticated boundary
protocol without patching OpenShell.

The host supervisor owns gateway authentication and network policy enforcement.
Its SSH relay lives in a private temporary directory with a short path to fit
macOS Unix-socket limits. Its process and directory are owned by the driver.

The guest entrypoint installs IPv4/IPv6 default-deny firewall rules, permits
loopback and replies to incoming control connections, and points DNS at
127.0.0.53. It then copies the read-only bootstrap/TLS inputs to /run/trybox,
prepares the public CA directory and workspace, and execs the upstream
capability-free boundary launcher. No privileged parent remains.

The boundary listens on port 17672. Apple Container publishes this on a unique
host port bound to 127.0.0.1. SandboxTransport::Tcp uses pinned per-generation TLS;
the guest uses BoundaryListener::TlsTcp. Unix sockets are never shared through
virtiofs. Only Linux binaries and bootstrap inputs are shared read-only; gateway
credentials remain on the host.

See BLOCKERS.md for validation and remaining lifecycle limitations.
