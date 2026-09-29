# Staging layout for apple-container sandboxes

Driver stages per-sandbox files on the host; the guest mounts these readonly.

## Host side

Root: `~/.local/state/openshell/apple-container-secrets/<namespace>/<sandbox-id>/`

Subdirectories (created 0700 via openshell_core::paths::create_dir_restricted):
  supervisor/    — mounted readonly at /.openshell/supervisor in the guest
  channel/sandbox/ — mounted readonly at /.openshell/channel/sandbox in the guest

## supervisor/.openshell/supervisor (mounted readonly at /.openshell/supervisor)

auth.json
  SupervisorAuthBundle (openshell_core::jwt::SupervisorAuthBundle), the
  `launch_authentication.supervisor` field parsed from the create-sandbox
  request.

backend-descriptor.json
  SandboxRuntimeDescriptor (openshell_sandbox_backend::boundary_protocol::SandboxRuntimeDescriptor). Build with:
    boundary_id = sandbox.id
    generation = SandboxGenerationId::new (uuid v7)
    session_id = launch_authentication.supervisor.session_id
    transport = SandboxTransport::Unix { socket_path: "/.openshell/channel/sandbox/sandbox.sock" }
      -- same as podman. Apple Container supports unix sockets across processes
      -- inside one VM.
    tls = SandboxTlsClientConfig {
            server_name: tls.server_name,
            trust_anchor_pem: tls.trust_anchor_pem,
          }
            where `tls = generate_sandbox_tls_material(session_id)?`
    host_gateway_ip = Some(192.168.64.1) -- from `container network list --format json | jq .ipv4Gateway`
    resource_claims = {
      "apple.container.container_id": container_name_for_sandbox(sandbox),
      "apple.container.image": sandbox_image(sandbox, &config),
    }
    workload_identity = ResolvedWorkloadIdentity::new(
      uid=1000,
      gid=1000,
      supplementary_gids=[],
      source="trybox",
      resource_digest=<sha256 of sandbox.id + generation>,
    )?
    outer_fence = built per openshell_isolation_interface::contract::OuterFenceGuarantees::from_enforcement_evidence (see podman OuterFenceEvidence pattern)

## channel/sandbox (mounted readonly at /.openshell/channel/sandbox)

bootstrap.json
  BoundaryConfig (openshell_sandbox_backend::boundary_protocol::BoundaryConfig). Build with:
    boundary_id = sandbox.id
    generation = (same as above)
    session_id = (same as above)
    session_rotation = launch_authentication.supervisor.session_rotation
    auth_epoch = launch_authentication.supervisor.auth_epoch
    gateway_id = launch_authentication.gateway_id
    verification_keys = launch_authentication.verification_keys mapped to
      Vec<GatewayVerificationKey> (string-utf8 of public_key_pem)
    listener = BoundaryListener::Unix {
      socket_path: "/.openshell/channel/sandbox/sandbox.sock",
      tls: SandboxTlsServerConfig {
        certificate_chain_path: "/.openshell/channel/sandbox/server.crt",
        private_key_path: "/.openshell/channel/sandbox/server.key",
      },
    }
      -- use Unix socket like podman; the supervisor spawns/openshell-sandbox
      -- inside the same VM so a UDS is the natural transport.
    resource_claims = (same BTreeMap as above)
    workload_identity = (same as above)
    outer_fence = (same as above)

server.crt
  PEM bytes of tls.certificate_chain_pem from generate_sandbox_tls_material

server.key
  PEM bytes of tls.private_key_pem from generate_sandbox_tls_material

## Reference

openshell-driver-podman/src/isolation.rs bootstrap_archives() — the exact JSON
shape pattern being mirrored here, with SandboxTransport/BoundaryListener::Unix.
