// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Apple Container compute-driver implementation.

use crate::cli::{
    AppleContainerCli, AppleContainerCliError, AppleContainerListEntry, AppleContainerNetworkEntry,
};
use crate::config::AppleContainerComputeConfig;
use futures::Stream;
use openshell_core::driver_utils::{
    LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID, LABEL_SANDBOX_NAME,
    LABEL_SANDBOX_NAMESPACE,
};
use openshell_core::proto::compute::v1::{
    DriverCondition, DriverSandbox, DriverSandboxSpec, DriverSandboxStatus,
    GetCapabilitiesResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesSandboxEvent, watch_sandboxes_event,
};
use openshell_isolation_interface::contract::{
    OuterFenceGuarantee, OuterFenceGuarantees, ResolvedWorkloadIdentity,
};
use openshell_sandbox_backend::boundary_protocol::{
    BoundaryConfig, BoundaryListener, GatewayVerificationKey, SandboxRuntimeDescriptor,
    SandboxTlsClientConfig, SandboxTlsServerConfig, SandboxTransport,
    generate_sandbox_tls_material,
};
use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tracing::{info, warn};

const CONTAINER_PREFIX: &str = "openshell-sandbox-";
const VOLUME_PREFIX: &str = "openshell-sandbox-";
const SUPERVISOR_DIR_MOUNT_PATH: &str = "/opt/openshell/bin";
const TRYBOX_ENTRYPOINT_BIN: &str = "trybox-entrypoint";
const BOUNDARY_PORT: u16 = 17672;
const CHANNEL_RUNTIME_DIR: &str = "/run/trybox";
const CHANNEL_STATE_DIR_MOUNT_PATH: &str = "/.openshell/channel";
const AUTH_BUNDLE_FILE: &str = "auth.json";
const BACKEND_DESCRIPTOR_FILE: &str = "backend-descriptor.json";
/// Guest-visible sandbox subdirectory under the channel mount root. The
/// `openshell-sandbox --bootstrap` consumer expects
/// `<channel>/sandbox/bootstrap.json` plus per-generation TLS material.
const CHANNEL_SANDBOX_SUBDIR: &str = "sandbox";
const BOOTSTRAP_FILE: &str = "bootstrap.json";
const TLS_SERVER_CERT_FILE: &str = "server.crt";
const TLS_SERVER_KEY_FILE: &str = "server.key";
const SANDBOX_WORKDIR: &str = "/sandbox";
const SUPERVISOR_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const TRANSIENT_STOPPED_LAUNCH_GRACE_MS: i64 = 30_000;
const WATCH_BUFFER: usize = 64;
const DEFAULT_WORKLOAD_UID: u32 = 1000;
const DEFAULT_WORKLOAD_GID: u32 = 1000;
/// Environment variable override for the macOS host-built supervisor binary
/// location. Used by trybox install so operators can swap binaries without
/// touching the driver's guest-bin tree.
pub const HOST_SUPERVISOR_BIN_ENV: &str = "OPENSHELL_APPLE_CONTAINER_HOST_SUPERVISOR_BIN";
/// Default host supervisor path when the env override is unset. Expected layout:
/// `~/.local/share/trybox/host-bin/openshell-supervisor` (aarch64-apple-darwin).
pub const HOST_SUPERVISOR_BIN_DEFAULT: &str = "host-bin/openshell-supervisor";

#[derive(Debug)]
struct AppleSecretStagingDirs {
    channel_mount_dir: PathBuf,
    boundary_host_port: u16,
}

struct HostSupervisor {
    child: tokio::process::Child,
    _socket_dir: tempfile::TempDir,
}

/// Stream type returned by the Apple Container driver watch API.
pub type WatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, String>> + Send + 'static>>;

/// Queried by the driver to decide when a running sandbox is usable.
///
/// Apple Container can report that the container process has started before
/// the `OpenShell` supervisor has connected back to the gateway. The compute
/// plane treats the sandbox as Ready only after this signal flips true.
pub trait SupervisorReadiness: Send + Sync + 'static {
    /// Return true once the sandbox supervisor has an active gateway session.
    fn is_supervisor_connected(&self, sandbox_id: &str) -> bool;
}

/// Readiness probe that always reports "connected."
///
/// Used by the standard gateway composition today because
/// [`openshell_server::ComputeDriverBuildContext`] does not yet expose the
/// supervisor-session registry; the resulting driver treats container-start
/// as sufficient and skips rider-on-supervisor readiness.
pub struct AlwaysReadySupervisor;

impl SupervisorReadiness for AlwaysReadySupervisor {
    fn is_supervisor_connected(&self, _sandbox_id: &str) -> bool {
        true
    }
}

/// Compute driver that manages sandboxes with Apple's container runtime.
#[derive(Clone)]
pub struct AppleContainerComputeDriver {
    cli: AppleContainerCli,
    config: AppleContainerComputeConfig,
    gateway_bind_addresses: Vec<SocketAddr>,
    supervisor_readiness: Arc<dyn SupervisorReadiness>,
    events: broadcast::Sender<WatchSandboxesEvent>,
    /// Per-sandbox supervisor child processes the driver owns on the host.
    /// Inserted at `create_sandbox`; removed when the child exits normally; killed
    /// on `delete_sandbox`. Keyed by sandbox id.
    supervisor_children: Arc<tokio::sync::Mutex<std::collections::HashMap<String, HostSupervisor>>>,
}

impl std::fmt::Debug for AppleContainerComputeDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleContainerComputeDriver")
            .field("cli", &self.cli)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl AppleContainerComputeDriver {
    /// Create and validate a new Apple Container driver.
    ///
    /// # Errors
    /// Returns an error when the configured `container` CLI is unavailable or
    /// reports an unhealthy Apple Container service.
    pub async fn new(
        config: AppleContainerComputeConfig,
        supervisor_readiness: Arc<dyn SupervisorReadiness>,
    ) -> Result<Self, Status> {
        let cli = AppleContainerCli::new(config.container_bin.clone());
        cli.health().await.map_err(status_from_cli)?;
        let gateway_bind_addresses = gateway_bind_addresses_from_networks(&cli, &config).await?;
        Ok(Self {
            cli,
            config,
            gateway_bind_addresses,
            supervisor_readiness,
            events: broadcast::channel(WATCH_BUFFER).0,
            supervisor_children: Arc::new(
                tokio::sync::Mutex::new(std::collections::HashMap::new()),
            ),
        })
    }

    /// Return driver capability metadata.
    #[must_use]
    pub fn capabilities(&self) -> GetCapabilitiesResponse {
        GetCapabilitiesResponse {
            driver_name: "apple-container".to_string(),
            driver_version: openshell_core::VERSION.to_string(),
            default_image: self.config.default_image.clone(),
            gateway_manages_lifecycle: true,
            supports_sandbox_authentication: false,
            driver_reports_runtime_readiness: false,
            resource_capabilities: None,
            rootfs_tar_staging_dir: String::new(),
            rootfs_tar_max_bytes: 0,
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                openshell_core::extension_protocol::ExtensionFamily::Compute,
                "openshell/apple-container",
                openshell_core::VERSION,
                [],
            )),
            resource_admission_policy:
                openshell_core::resource_admission::DriverAdmissionConfig::default()
                    .acknowledgement(),
        }
    }

    /// Return gateway listener addresses required by Apple container VMs.
    #[must_use]
    pub fn gateway_bind_addresses(&self) -> Vec<SocketAddr> {
        self.gateway_bind_addresses.clone()
    }

    /// Validate a sandbox before creation.
    pub fn validate_sandbox_create(&self, sandbox: &DriverSandbox) -> Result<(), Status> {
        if sandbox.name.trim().is_empty() {
            return Err(Status::failed_precondition("sandbox name is required"));
        }
        if sandbox.id.trim().is_empty() {
            return Err(Status::failed_precondition("sandbox id is required"));
        }
        if sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.resource_requirements.as_ref())
            .and_then(|requirements| requirements.gpu.as_ref())
            .is_some()
        {
            return Err(Status::failed_precondition(
                "apple-container driver does not support GPU sandboxes",
            ));
        }
        validate_container_name(&container_name_for_sandbox(sandbox))?;
        validate_sandbox_template(sandbox)?;
        if sandbox_image(sandbox, &self.config).trim().is_empty() {
            return Err(Status::failed_precondition(
                "no sandbox image configured: set default_image in [openshell.drivers.apple-container] or provide a template image",
            ));
        }
        Ok(())
    }

    /// Create and start one sandbox.
    pub async fn create_sandbox(&self, sandbox: &DriverSandbox) -> Result<(), Status> {
        self.validate_sandbox_create(sandbox)?;
        validate_sandbox_auth(sandbox)?;
        if self
            .find_managed_entry(&sandbox.id, &sandbox.name)
            .await?
            .is_some()
        {
            return Err(Status::already_exists("sandbox already exists"));
        }
        let volume = volume_name(&sandbox.id);
        self.cli
            .create_volume(&volume, &managed_labels(sandbox, &self.config))
            .await
            .map_err(status_from_cli)?;
        let args = match self.create_args(sandbox).await {
            Ok(args) => args,
            Err(err) => {
                self.cleanup_volume_with_warning(&volume, &sandbox.id, "create-args-failed")
                    .await;
                cleanup_secret_staging_dir(&sandbox.id, &self.config);
                return Err(err);
            }
        };
        if let Err(err) = self.cli.run_detached(&args).await {
            // `container run --detach` can leave a partially-created container behind
            // when it fails after the create step; best-effort delete it before
            // cleaning up the volume and staged credentials it references.
            let container_name = container_name_for_sandbox(sandbox);
            if let Err(delete_err) = self.cli.delete(&container_name).await {
                let status = status_from_cli(delete_err);
                if status.code() != tonic::Code::NotFound {
                    warn!(
                        sandbox_id = %sandbox.id,
                        container = %container_name,
                        error = %status,
                        "Failed to delete partial Apple sandbox container"
                    );
                }
            }
            self.cleanup_volume_with_warning(&volume, &sandbox.id, "container-run-failed")
                .await;
            cleanup_secret_staging_dir(&sandbox.id, &self.config);
            return Err(status_from_cli(err));
        }

        // Spawn the macOS host-side supervisor AFTER the boundary container is up.
        // The supervisor dials the boundary over generation-pinned TLS on loopback.
        // If the supervisor fails to spawn, clean up the partial sandbox state.
        let launch_authentication = decode_launch_authentication(sandbox)?;
        if let Err(spawn_err) = self
            .spawn_host_supervisor(sandbox, &launch_authentication)
            .await
        {
            warn!(
                sandbox_id = %sandbox.id,
                error = %spawn_err,
                "host supervisor spawn failed; cleaning up partially-created sandbox"
            );
            let container_name = container_name_for_sandbox(sandbox);
            if let Err(delete_err) = self.cli.delete(&container_name).await {
                let status = status_from_cli(delete_err);
                if status.code() != tonic::Code::NotFound {
                    warn!(
                        sandbox_id = %sandbox.id,
                        container = %container_name,
                        error = %status,
                        "Failed to delete Apple container after supervisor spawn failure"
                    );
                }
            }
            self.cleanup_volume_with_warning(&volume, &sandbox.id, "supervisor-spawn-failed")
                .await;
            cleanup_secret_staging_dir(&sandbox.id, &self.config);
            return Err(spawn_err);
        }
        Ok(())
    }

    /// Stop a sandbox without deleting it.
    pub async fn stop_sandbox(&self, sandbox_id: &str, sandbox_name: &str) -> Result<(), Status> {
        require_sandbox_identifier(sandbox_id, sandbox_name)?;
        let entry = self
            .find_managed_entry(sandbox_id, sandbox_name)
            .await?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        // Terminate the host supervisor before stopping the container so
        // the supervisor doesn't race to reconnect to a dead boundary.
        // start_sandbox will re-spawn it from the still-intact staging dir.
        self.terminate_host_supervisor(sandbox_id).await;
        self.cli
            .stop(&entry.id, self.config.stop_timeout_secs)
            .await
            .map_err(status_from_cli)
    }

    /// Start a stopped Apple-container sandbox, honoring the launch
    /// authentication contract.
    ///
    /// The Apple driver stages supervisor secrets into a per-sandbox host
    /// directory at container-create time.  A sandbox that is already running
    /// cannot accept a new launch-authentication bundle, so a non-empty
    /// `launch_authentication` payload against a running container is
    /// rejected; the gateway must recreate the sandbox instead.
    pub async fn start_sandbox(
        &self,
        sandbox_id: &str,
        generation_id: &str,
        launch_authentication: &[u8],
    ) -> Result<(), Status> {
        openshell_core::sandbox_generation::SandboxGenerationId::parse(generation_id.to_string())
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let entry = self
            .find_managed_entry(sandbox_id, "")
            .await?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        if apple_container_state_needs_resume(&entry.status.state) {
            // Re-spawn the host supervisor after container restart.
            // stop_sandbox kills the supervisor; start_sandbox must bring it
            // back or the boundary waits forever for a supervisor connection.
            // The gateway issues fresh launch_authentication on StartSandbox
            // (new generation_id, new JWT) — re-stage it before spawning.
            if !launch_authentication.is_empty() {
                let sandbox = DriverSandbox {
                    id: sandbox_id.to_string(),
                    name: String::new(),
                    spec: Some(DriverSandboxSpec {
                        launch_authentication: launch_authentication.to_vec(),
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                let auth = decode_launch_authentication(&sandbox)?;

                // 1. Read the original boundary host port from the existing
                //    backend-descriptor.json BEFORE cleanup.  The container's
                //    --publish mapping is immutable from creation; the re-staged
                //    descriptor must advertise the same port or the supervisor
                //    dials a port where nothing listens.
                let reuse_port =
                    secret_staging_dir(&sandbox.id, Some(&self.config.sandbox_namespace))
                        .ok()
                        .and_then(|root| {
                            let path = root.join("supervisor").join(BACKEND_DESCRIPTOR_FILE);
                            std::fs::read(&path).ok()
                        })
                        .and_then(|bytes| {
                            serde_json::from_slice::<SandboxRuntimeDescriptor>(&bytes)
                                .map_err(|e| {
                                    warn!(
                                        sandbox_id = %sandbox_id,
                                        error = %e,
                                        "failed to parse old descriptor for port reuse"
                                    );
                                    e
                                })
                                .ok()
                        })
                        .and_then(|desc| match desc.transport {
                            SandboxTransport::Tcp { addresses, .. } => addresses.into_iter().next(),
                            _ => None,
                        })
                        .map(|addr| addr.port());

                // 2. Wipe old staging + re-stage with NEW auth + reused port.
                //    This must happen BEFORE `container start` because the guest
                //    entrypoint copies bootstrap.json + TLS certs from the
                //    bind-mounted channel dir at boot — staging after start is
                //    too late and the guest would use OLD TLS material.
                cleanup_secret_staging_dir(&sandbox.id, &self.config);
                let reuse_addr =
                    reuse_port.map(|port| SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)));
                if let Err(stage_err) =
                    write_secret_staging_materials(&sandbox, &self.config, &auth, None, reuse_addr)
                        .await
                {
                    warn!(
                        sandbox_id = %sandbox_id,
                        error = %stage_err,
                        "re-staging secret materials failed during sandbox start"
                    );
                    return Err(stage_err);
                }

                // 3. NOW start the container — the entrypoint copies the NEW
                //    bootstrap + TLS from the re-staged channel mount.
                self.cli.start(&entry.id).await.map_err(status_from_cli)?;

                // 4. Wait for the container to reach "running" state.
                //    The gateway polls sandbox snapshots and will mark the
                //    sandbox Error if it sees "stopped" during the brief
                //    window between `container start` returning and the VM
                //    actually resuming.
                for _ in 0..30 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    if let Ok(refreshed) = self.find_managed_entry(sandbox_id, "").await {
                        if let Some(e) = refreshed {
                            if e.status.state == "running" {
                                break;
                            }
                        }
                    }
                }

                // 5. Spawn the host supervisor with the NEW descriptor.
                if let Err(spawn_err) = self.spawn_host_supervisor(&sandbox, &auth).await {
                    warn!(
                        sandbox_id = %sandbox_id,
                        error = %spawn_err,
                        "host supervisor re-spawn failed during sandbox start"
                    );
                }
            } else {
                // No new launch_authentication — just restart the container.
                self.cli.start(&entry.id).await.map_err(status_from_cli)?;
            }
            return Ok(());
        }
        if launch_authentication.is_empty() {
            // Idempotent resume: gateway re-issued StartSandbox for an
            // already-running sandbox and is not requesting new credentials.
            return Ok(());
        }
        Err(Status::failed_precondition(
            "apple-container sandbox must be recreated to apply new launch authentication; \
             Apple secret staging happens only at container bake time",
        ))
    }

    /// Delete a sandbox and its driver-owned secret staging directory.
    pub async fn delete_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<bool, Status> {
        require_sandbox_identifier(sandbox_id, sandbox_name)?;
        // Kill the host-side supervisor first so its kill-on-drop propagation has
        // time to exit the boundary cleanly before we destroy the container.
        self.terminate_host_supervisor(sandbox_id).await;
        let Some(entry) = self.find_managed_entry(sandbox_id, sandbox_name).await? else {
            if !sandbox_id.is_empty() {
                self.cleanup_volume_with_warning(
                    &volume_name(sandbox_id),
                    sandbox_id,
                    "container-not-found",
                )
                .await;
                cleanup_secret_staging_dir(sandbox_id, &self.config);
            }
            return Ok(false);
        };
        let resolved_id = entry
            .configuration
            .labels
            .get(LABEL_SANDBOX_ID)
            .cloned()
            .unwrap_or_else(|| sandbox_id.to_string());
        let deleted = self.cli.delete(&entry.id).await.map_err(status_from_cli)?;
        // Host supervisor may have respawned or belong to the resolved id variant —
        // terminate that as well.
        if resolved_id != sandbox_id {
            self.terminate_host_supervisor(&resolved_id).await;
        }
        if !resolved_id.is_empty() {
            self.cleanup_volume_with_warning(
                &volume_name(&resolved_id),
                &resolved_id,
                "container-deleted",
            )
            .await;
            cleanup_secret_staging_dir(&resolved_id, &self.config);
        }
        if deleted && !resolved_id.is_empty() {
            self.emit_deleted_event(&resolved_id);
        }
        Ok(deleted)
    }

    async fn find_managed_entry(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<AppleContainerListEntry>, Status> {
        Ok(self
            .list_entries()
            .await?
            .into_iter()
            .filter(|entry| managed_entry(entry, &self.config))
            .find(|entry| entry_matches(entry, sandbox_id, sandbox_name)))
    }

    /// Fetch one sandbox by name.
    pub async fn get_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<DriverSandbox>, Status> {
        let sandboxes = self.list_entries().await?;
        Ok(sandboxes
            .into_iter()
            .filter(|entry| managed_entry(entry, &self.config))
            .find(|entry| entry_matches(entry, sandbox_id, sandbox_name))
            .and_then(|entry| driver_sandbox_from_entry(entry, self.supervisor_readiness.as_ref())))
    }

    /// List all OpenShell-managed Apple containers.
    pub async fn list_sandboxes(&self) -> Result<Vec<DriverSandbox>, Status> {
        let mut sandboxes = self
            .list_entries()
            .await?
            .into_iter()
            .filter(|entry| managed_entry(entry, &self.config))
            .filter_map(|entry| {
                driver_sandbox_from_entry(entry, self.supervisor_readiness.as_ref())
            })
            .collect::<Vec<_>>();
        sandboxes.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
        Ok(sandboxes)
    }

    /// Start a polling watch stream for sandbox snapshots.
    pub fn watch_sandboxes(&self) -> Result<WatchStream, Status> {
        let driver = self.clone();
        let mut events = self.events.subscribe();
        let (tx, rx) = mpsc::channel(WATCH_BUFFER);
        tokio::spawn(async move {
            let mut previous: BTreeMap<String, DriverSandbox> = BTreeMap::new();
            let mut poll = tokio::time::interval(Duration::from_secs(2));
            poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = poll.tick() => {
                        if tx.is_closed() {
                            return;
                        }
                        match driver.list_sandboxes().await {
                            Ok(sandboxes) => {
                                let current = sandboxes
                                    .iter()
                                    .map(|sandbox| (sandbox.id.clone(), sandbox.clone()))
                                    .collect::<BTreeMap<_, _>>();
                                if !send_snapshot_delta(&tx, &previous, &current).await {
                                    return;
                                }
                                previous = current;
                            }
                            Err(err) => {
                                warn!(
                                    error = %err,
                                    "Apple sandbox watch poll failed"
                                );
                            }
                        }
                    }
                    event = events.recv() => {
                        match event {
                            Ok(event) => {
                                apply_watch_event_to_cache(&mut previous, &event);
                                if tx.send(Ok(event)).await.is_err() {
                                    return;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!(
                                    skipped,
                                    "Apple sandbox watch event receiver lagged; polling will resynchronize state"
                                );
                            }
                            Err(broadcast::error::RecvError::Closed) => return,
                        }
                    }
                }
            }
        });
        Ok(Box::pin(ReceiverStream::new(rx)))
    }

    fn emit_deleted_event(&self, sandbox_id: &str) {
        let _ = self
            .events
            .send(watch_deleted_event(sandbox_id.to_string()));
    }

    async fn cleanup_volume_with_warning(&self, volume: &str, sandbox_id: &str, reason: &str) {
        match self.cli.delete_volume(volume).await {
            Ok(_) => {}
            Err(err) => {
                let status = status_from_cli(err);
                warn!(
                    sandbox_id,
                    volume,
                    reason,
                    error = %status,
                    "Failed to delete Apple sandbox volume"
                );
            }
        }
    }

    /// Resolve the absolute path to the host-side openshell-supervisor binary.
    ///
    /// Honors `OPENSHELL_APPLE_CONTAINER_HOST_SUPERVISOR_BIN`; otherwise
    /// returns `~/.local/share/trybox/host-bin/openshell-supervisor` when the
    /// `host_supervisor_bin` config field is unset.
    pub fn host_supervisor_bin(&self) -> PathBuf {
        if let Ok(override_path) = std::env::var(crate::driver::HOST_SUPERVISOR_BIN_ENV)
            && !override_path.trim().is_empty()
        {
            return PathBuf::from(override_path);
        }
        if let Some(cfg_path) = self.config.host_supervisor_bin.as_ref()
            && !cfg_path.as_os_str().is_empty()
        {
            return cfg_path.clone();
        }
        // default: $HOME/.local/share/trybox/host-bin/openshell-supervisor
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
        PathBuf::from(home)
            .join(".local/share/trybox")
            .join(HOST_SUPERVISOR_BIN_DEFAULT)
    }

    /// Kill the host-side openshell-supervisor process for `sandbox_id` if one is
    /// running, and remove it from the tracked map. Safe to call when nothing is
    /// present; errors are swallowed to keep delete paths idempotent.
    async fn terminate_host_supervisor(&self, sandbox_id: &str) {
        let mut guard = self.supervisor_children.lock().await;
        if let Some(mut child) = guard.remove(sandbox_id) {
            if let Err(err) = child.child.kill().await {
                warn!(
                    sandbox_id,
                    error = %err,
                    "failed to terminate host supervisor; relying on kill-on-drop"
                );
            }
        }
    }

    async fn spawn_host_supervisor(
        &self,
        sandbox: &DriverSandbox,
        launch_authentication: &openshell_core::jwt::SandboxLaunchAuthentication,
    ) -> Result<(), Status> {
        let staging_root = secret_staging_dir(&sandbox.id, Some(&self.config.sandbox_namespace))
            .map_err(|err| {
                Status::internal(format!(
                    "resolve per-sandbox staging dir for {} failed: {err}",
                    sandbox.id
                ))
            })?;
        let supervisor_state = staging_root.join("supervisor");
        let auth_bundle_path = supervisor_state.join(AUTH_BUNDLE_FILE);
        let backend_descriptor_path = supervisor_state.join(BACKEND_DESCRIPTOR_FILE);
        if !auth_bundle_path.is_file() || !backend_descriptor_path.is_file() {
            return Err(Status::failed_precondition(format!(
                "sandbox {} supervisor staging incomplete ({} / {})",
                sandbox.id,
                auth_bundle_path.display(),
                backend_descriptor_path.display()
            )));
        }

        let supervisor_bin = self.host_supervisor_bin();
        if !supervisor_bin.is_file() {
            return Err(Status::failed_precondition(format!(
                "host supervisor binary missing: {}",
                supervisor_bin.display()
            )));
        }

        let sandbox_workspace = staging_root.join("workspace");
        let supervisor_log_dir = staging_root.join("logs");
        let _ = std::fs::create_dir_all(&sandbox_workspace);
        let _ = std::fs::create_dir_all(&supervisor_log_dir);

        let supervisor_stdout = supervisor_log_dir.join("supervisor.stdout.log");
        let supervisor_stderr = supervisor_log_dir.join("supervisor.stderr.log");
        let stdout = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&supervisor_stdout)
            .map_err(|err| {
                Status::internal(format!(
                    "open supervisor log {}: {err}",
                    supervisor_stdout.display()
                ))
            })?;
        let stderr = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&supervisor_stderr)
            .map_err(|err| {
                Status::internal(format!(
                    "open supervisor log {}: {err}",
                    supervisor_stderr.display()
                ))
            })?;

        // macOS Unix sockets have a short path limit, so do not put this socket
        // beneath the deeply nested XDG staging directory. TempDir is private
        // and stays alive for exactly as long as its supervisor child.
        let socket_dir = tempfile::Builder::new()
            .prefix("trybox-ssh-")
            .tempdir_in("/tmp")
            .map_err(|err| Status::internal(format!("create SSH socket directory: {err}")))?;
        let mut command = tokio::process::Command::new(&supervisor_bin);
        command
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(stdout))
            .stderr(std::process::Stdio::from(stderr))
            .arg(format!(
                "--backend-descriptor-file={}",
                backend_descriptor_path.display()
            ))
            .arg(format!("--auth-bundle-file={}", auth_bundle_path.display()))
            .arg("--ssh-socket-path")
            .arg(socket_dir.path().join("ssh.sock"))
            .arg("--workdir")
            .arg(SANDBOX_WORKDIR)
            .env(
                openshell_core::sandbox_env::PROXY_TLS_DIR,
                staging_root.join("proxy-tls"),
            )
            .env(
                openshell_core::sandbox_env::MAIN_PROCESS_SPEC,
                openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(
                    sandbox.spec.as_ref(),
                )
                .unwrap_or_default(),
            )
            .env(openshell_core::sandbox_env::SANDBOX_ID, &sandbox.id)
            .env(openshell_core::sandbox_env::SANDBOX, &sandbox.name)
            .env(
                openshell_core::sandbox_env::ENDPOINT,
                // The host supervisor runs on the macOS host, not in the guest.
                // `host.container.internal` (the guest→host resolver) does not
                // resolve from the host itself; use the explicit loopback listen
                // address the gateway serves on.
                {
                    let ep = self.config.effective_host_grpc_endpoint();
                    info!(endpoint = %ep, "host supervisor OPENSHELL_ENDPOINT");
                    ep
                },
            )
            .env(
                openshell_core::sandbox_env::ADMITTED_ISOLATION_BACKEND,
                openshell_sandbox_backend::BACKEND_NAME,
            )
            .env(
                openshell_core::sandbox_env::LOG_LEVEL,
                openshell_core::driver_utils::sandbox_log_level(sandbox, &self.config.log_level),
            );
        if let (Some(ca), Some(cert), Some(key)) = (
            self.config.guest_tls_ca.as_ref(),
            self.config.guest_tls_cert.as_ref(),
            self.config.guest_tls_key.as_ref(),
        ) {
            command
                .env(openshell_core::sandbox_env::TLS_CA, ca)
                .env(openshell_core::sandbox_env::TLS_CERT, cert)
                .env(openshell_core::sandbox_env::TLS_KEY, key);
        }
        // The HOST supervisor (as distinct from the guest sandbox) also needs the
        // host-side mTLS material to present to the gateway, or the gateway's
        // client-CA check rejects the dial with `permission denied`.
        if let (Some(ca), Some(cert), Some(key)) = (
            self.config.host_tls_ca.as_ref(),
            self.config.host_tls_cert.as_ref(),
            self.config.host_tls_key.as_ref(),
        ) {
            command
                .env(openshell_core::sandbox_env::TLS_CA, ca)
                .env(openshell_core::sandbox_env::TLS_CERT, cert)
                .env(openshell_core::sandbox_env::TLS_KEY, key);
        } else {
            warn!(
                "apple-container driver host mTLS not configured; host supervisor cannot present a client cert — gateway TLS will reject"
            );
        }

        let child = command.spawn().map_err(|err| {
            Status::internal(format!(
                "spawn host supervisor '{}' failed: {err}",
                supervisor_bin.display()
            ))
        })?;
        let mut guard = self.supervisor_children.lock().await;
        guard.insert(
            sandbox.id.clone(),
            HostSupervisor {
                child,
                _socket_dir: socket_dir,
            },
        );

        let _ = launch_authentication;
        Ok(())
    }

    async fn list_entries(&self) -> Result<Vec<AppleContainerListEntry>, Status> {
        self.cli.list().await.map_err(status_from_cli)
    }

    async fn create_args(&self, sandbox: &DriverSandbox) -> Result<Vec<String>, Status> {
        self.create_args_with_secret_staging_base(sandbox, None)
            .await
    }

    async fn create_args_with_secret_staging_base(
        &self,
        sandbox: &DriverSandbox,
        secret_staging_base: Option<&Path>,
    ) -> Result<Vec<String>, Status> {
        let container_name = container_name_for_sandbox(sandbox);
        let image = sandbox_image(sandbox, &self.config);
        if image.trim().is_empty() {
            return Err(Status::failed_precondition(
                "no sandbox image configured: set default_image in [openshell.drivers.apple-container] or provide a template image",
            ));
        }

        let supervisor_dir = supervisor_bin_dir(&self.config.supervisor_bin_dir)?;
        if !supervisor_dir.join(TRYBOX_ENTRYPOINT_BIN).is_file() {
            return Err(Status::failed_precondition(format!(
                "trybox-entrypoint not found in supervisor bin dir {}",
                supervisor_dir.display()
            )));
        }
        let launch_authentication = decode_launch_authentication(sandbox)?;
        let staging_dirs = write_secret_staging_materials(
            sandbox,
            &self.config,
            &launch_authentication,
            secret_staging_base,
            None,
        )
        .await?;
        let mut args = vec!["--name".to_string(), container_name];
        for label in managed_labels(sandbox, &self.config) {
            args.push("--label".to_string());
            args.push(label);
        }
        args.extend([
            // Sandbox images may set USER sandbox for interactive shells. The
            // supervisor itself must start as root so it can create the network
            // namespace, prepare writable paths, and then drop to the policy user.
            "--user".to_string(),
            "0:0".to_string(),
            "--workdir".to_string(),
            SANDBOX_WORKDIR.to_string(),
            "--volume".to_string(),
            format!("{}:{SANDBOX_WORKDIR}", volume_name(&sandbox.id)),
            "--mount".to_string(),
            crate::cli::readonly_bind_mount(&supervisor_dir, SUPERVISOR_DIR_MOUNT_PATH),
            "--mount".to_string(),
            crate::cli::readonly_bind_mount(
                &staging_dirs.channel_mount_dir,
                CHANNEL_STATE_DIR_MOUNT_PATH,
            ),
            "--publish".to_string(),
            format!(
                "127.0.0.1:{}:{BOUNDARY_PORT}",
                staging_dirs.boundary_host_port
            ),
            "--entrypoint".to_string(),
            format!("{SUPERVISOR_DIR_MOUNT_PATH}/{TRYBOX_ENTRYPOINT_BIN}"),
        ]);

        for (key, value) in sandbox_environment(sandbox, &self.config) {
            args.push("--env".to_string());
            args.push(format!("{key}={value}"));
        }

        if let Some(memory) = sandbox_memory_limit(sandbox) {
            args.push("--memory".to_string());
            args.push(memory);
        }
        if let Some(cpus) = sandbox_cpu_limit(sandbox)? {
            args.push("--cpus".to_string());
            args.push(cpus);
        }

        // Capability set matches upstream `launch-capability-free` (podman container.rs:1526): the
        // boundary starts as root with the minimal caps it needs to chown workspace + drop to
        // the workload identity. No broader admin caps (SYS_ADMIN / NET_ADMIN / SYS_PTRACE / SYSLOG
        // Caps the entrypoint/PID-1 needs inside the Apple VM:
        //   - SYS_ADMIN: to re-bind /proc/sys/net writable (Apple lacks --sysctl)
        //   - CHOWN, SETGID, SETUID, SETPCAP: required by upstream launch-capability-free
        //     so it can chown the workspace and drop credentials to the workload
        //     identity. After the boundary runs at uid 1000, no further privileged
        //     operations take place.
        for cap in [
            "SYS_ADMIN",
            "NET_ADMIN",
            "CHOWN",
            "SETGID",
            "SETUID",
            "SETPCAP",
        ] {
            args.push("--cap-add".to_string());
            args.push(cap.to_string());
        }
        args.push(image);
        Ok(args)
    }
}

fn status_from_cli(err: AppleContainerCliError) -> Status {
    if matches!(&err, AppleContainerCliError::Unhealthy { .. }) {
        return Status::failed_precondition(err.to_string());
    }
    let message = err.to_string();
    if message.contains("already exists") || message.contains("exists") {
        Status::already_exists(message)
    } else if message.contains("not found") || message.contains("does not exist") {
        Status::not_found(message)
    } else {
        Status::internal(message)
    }
}

async fn send_snapshot_delta(
    tx: &mpsc::Sender<Result<WatchSandboxesEvent, String>>,
    previous: &BTreeMap<String, DriverSandbox>,
    current: &BTreeMap<String, DriverSandbox>,
) -> bool {
    for (sandbox_id, sandbox) in current {
        if previous.get(sandbox_id) == Some(sandbox) {
            continue;
        }
        if tx
            .send(Ok(watch_sandbox_event(sandbox.clone())))
            .await
            .is_err()
        {
            return false;
        }
    }
    for sandbox_id in previous.keys() {
        if current.contains_key(sandbox_id) {
            continue;
        }
        if tx
            .send(Ok(watch_deleted_event(sandbox_id.clone())))
            .await
            .is_err()
        {
            return false;
        }
    }
    true
}

fn watch_sandbox_event(sandbox: DriverSandbox) -> WatchSandboxesEvent {
    WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::Sandbox(
            WatchSandboxesSandboxEvent {
                sandbox: Some(sandbox),
            },
        )),
    }
}

fn watch_deleted_event(sandbox_id: String) -> WatchSandboxesEvent {
    WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::Deleted(
            WatchSandboxesDeletedEvent { sandbox_id },
        )),
    }
}

fn apply_watch_event_to_cache(
    previous: &mut BTreeMap<String, DriverSandbox>,
    event: &WatchSandboxesEvent,
) {
    match event.payload.as_ref() {
        Some(watch_sandboxes_event::Payload::Sandbox(WatchSandboxesSandboxEvent {
            sandbox: Some(sandbox),
        })) => {
            previous.insert(sandbox.id.clone(), sandbox.clone());
        }
        Some(watch_sandboxes_event::Payload::Deleted(WatchSandboxesDeletedEvent {
            sandbox_id,
        })) => {
            previous.remove(sandbox_id);
        }
        _ => {}
    }
}

async fn gateway_bind_addresses_from_networks(
    cli: &AppleContainerCli,
    config: &AppleContainerComputeConfig,
) -> Result<Vec<SocketAddr>, Status> {
    if !config.grpc_endpoint.trim().is_empty() {
        return Ok(Vec::new());
    }
    let networks = cli.list_networks().await.map_err(status_from_cli)?;
    let Some(host_gateway) = apple_default_network_gateway(&networks) else {
        return Err(Status::failed_precondition(
            "apple-container driver could not find a default network ipv4Gateway; set grpc_endpoint to a reachable gateway URL",
        ));
    };
    Ok(vec![SocketAddr::new(host_gateway, config.gateway_port)])
}

fn apple_default_network_gateway(networks: &[AppleContainerNetworkEntry]) -> Option<IpAddr> {
    networks
        .iter()
        .find(|network| network.id == "default" || network.configuration.name == "default")
        .and_then(|network| network.status.ipv4_gateway)
        .or_else(|| {
            networks
                .iter()
                .find_map(|network| network.status.ipv4_gateway)
        })
}

fn apple_container_state_needs_resume(state: &str) -> bool {
    matches!(state, "created" | "stopped" | "exited")
}

#[cfg(test)]
fn apple_container_state_needs_shutdown_stop(state: &str) -> bool {
    matches!(state, "created" | "running")
}

const MAX_CONTAINER_NAME_LEN: usize = 63;

fn container_name_for_sandbox(sandbox: &DriverSandbox) -> String {
    let id_suffix = runtime_name_component(&sandbox.id);
    let friendly_name = runtime_name_component(&sandbox.name);
    if friendly_name.is_empty() {
        let mut base = format!("{CONTAINER_PREFIX}{id_suffix}");
        if base.len() > MAX_CONTAINER_NAME_LEN {
            base.truncate(MAX_CONTAINER_NAME_LEN);
        }
        return trim_runtime_name_tail(base);
    }

    // Apple container names are unique per runtime, not per OpenShell
    // namespace. Keep the id suffix even when the friendly name is long so two
    // sandboxes with the same display name cannot collide at the platform
    // layer.
    let reserved = CONTAINER_PREFIX.len() + 1 + id_suffix.len();
    if reserved >= MAX_CONTAINER_NAME_LEN {
        let mut base = format!("{CONTAINER_PREFIX}{id_suffix}");
        base.truncate(MAX_CONTAINER_NAME_LEN);
        return trim_runtime_name_tail(base);
    }

    let name_budget = MAX_CONTAINER_NAME_LEN - reserved;
    let truncated_name = if friendly_name.len() > name_budget {
        trim_runtime_name_tail(friendly_name[..name_budget].to_string())
    } else {
        friendly_name
    };
    format!("{CONTAINER_PREFIX}{truncated_name}-{id_suffix}")
}

fn volume_name(sandbox_id: &str) -> String {
    format!("{VOLUME_PREFIX}{}", sanitize_name(sandbox_id))
}

fn managed_labels(sandbox: &DriverSandbox, config: &AppleContainerComputeConfig) -> Vec<String> {
    let mut labels = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map(|template| template.labels.clone())
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    labels.insert(
        LABEL_MANAGED_BY.to_string(),
        LABEL_MANAGED_BY_VALUE.to_string(),
    );
    labels.insert(LABEL_SANDBOX_ID.to_string(), sandbox.id.clone());
    labels.insert(LABEL_SANDBOX_NAME.to_string(), sandbox.name.clone());
    labels.insert(
        LABEL_SANDBOX_NAMESPACE.to_string(),
        config.sandbox_namespace.clone(),
    );
    labels
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

fn sanitize_name(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    if out.is_empty() {
        "sandbox".to_string()
    } else {
        out
    }
}

fn runtime_name_component(value: &str) -> String {
    let trimmed = trim_runtime_name_tail(sanitize_name(value));
    if trimmed.is_empty() {
        "sandbox".to_string()
    } else {
        trimmed
    }
}

fn trim_runtime_name_tail(mut value: String) -> String {
    while value
        .chars()
        .last()
        .is_some_and(|ch| matches!(ch, '-' | '.' | '_'))
    {
        value.pop();
    }
    value
}

fn validate_container_name(name: &str) -> Result<(), Status> {
    if name.starts_with('-') || name.ends_with('-') {
        return Err(Status::failed_precondition(
            "apple-container sandbox name cannot start or end with '-'",
        ));
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(Status::failed_precondition(
            "apple-container sandbox name contains unsupported characters",
        ));
    }
    Ok(())
}

fn validate_sandbox_template(sandbox: &DriverSandbox) -> Result<(), Status> {
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox.spec is required"))?;
    let template = spec
        .template
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox.spec.template is required"))?;

    if !template.agent_socket_path.trim().is_empty() {
        return Err(Status::failed_precondition(
            "apple-container compute driver does not support template.agent_socket_path",
        ));
    }
    if template
        .platform_config
        .as_ref()
        .is_some_and(|config| !config.fields.is_empty())
    {
        return Err(Status::failed_precondition(
            "apple-container compute driver does not support template.platform_config",
        ));
    }
    if template
        .driver_config
        .as_ref()
        .is_some_and(|config| !config.fields.is_empty())
    {
        return Err(Status::failed_precondition(
            "apple-container compute driver does not support template.driver_config",
        ));
    }
    if let Some(resources) = template.resources.as_ref() {
        validate_resources(resources)?;
    }
    Ok(())
}

fn validate_sandbox_auth(sandbox: &DriverSandbox) -> Result<(), Status> {
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox.spec is required"))?;
    if !spec.launch_authentication.is_empty() {
        return Ok(());
    }

    Err(Status::failed_precondition(
        "apple-container sandboxes require gateway launch authentication; configure [openshell.gateway.gateway_jwt]",
    ))
}

fn validate_resources(
    resources: &openshell_core::proto::compute::v1::DriverResourceRequirements,
) -> Result<(), Status> {
    if !resources.cpu_request.trim().is_empty() {
        return Err(Status::failed_precondition(
            "apple-container compute driver does not support resources.requests.cpu",
        ));
    }
    if !resources.memory_request.trim().is_empty() {
        return Err(Status::failed_precondition(
            "apple-container compute driver does not support resources.requests.memory",
        ));
    }
    let _ = normalize_cpu_for_apple(&resources.cpu_limit)?;
    Ok(())
}

fn sandbox_image(sandbox: &DriverSandbox, config: &AppleContainerComputeConfig) -> String {
    sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map(|template| template.image.as_str())
        .filter(|image| !image.trim().is_empty())
        .unwrap_or(&config.default_image)
        .to_string()
}

fn sandbox_environment(
    sandbox: &DriverSandbox,
    config: &AppleContainerComputeConfig,
) -> BTreeMap<String, String> {
    // Only non-secret knobs are exported. The supervisor learns the gateway
    // endpoint from the sandbox_env::ENDPOINT variable so it can dial the
    // gateway, while tokens, JWTs, and TLS material travel exclusively
    // through the readonly-mounted `/.openshell/...` staging directories.
    let mut env = BTreeMap::new();
    if let Some(spec) = sandbox.spec.as_ref() {
        let mut user_env = BTreeMap::new();
        if let Some(template) = spec.template.as_ref() {
            user_env.extend(template.environment.clone());
        }
        user_env.extend(spec.environment.clone());
        for key in driver_owned_environment_keys() {
            user_env.remove(key);
        }
        user_env.remove(openshell_core::sandbox_env::SANDBOX_TOKEN);
        user_env.remove(openshell_core::sandbox_env::USER_ENVIRONMENT);
        user_env.remove(openshell_core::sandbox_env::TLS_CA);
        user_env.remove(openshell_core::sandbox_env::TLS_CERT);
        user_env.remove(openshell_core::sandbox_env::TLS_KEY);
        if !user_env.is_empty() {
            if let Ok(json) = serde_json::to_string(&user_env) {
                env.insert(
                    openshell_core::sandbox_env::USER_ENVIRONMENT.to_string(),
                    json,
                );
            }
            env.extend(user_env);
        }
    }
    for key in driver_owned_environment_keys() {
        env.remove(key);
    }
    env.remove(openshell_core::sandbox_env::SANDBOX_TOKEN);
    env.remove(openshell_core::sandbox_env::SANDBOX_TOKEN_FILE);
    env.remove(openshell_core::sandbox_env::TLS_CA);
    env.remove(openshell_core::sandbox_env::TLS_CERT);
    env.remove(openshell_core::sandbox_env::TLS_KEY);
    env.extend([
        ("HOME".to_string(), "/root".to_string()),
        ("PATH".to_string(), SUPERVISOR_PATH.to_string()),
        ("TERM".to_string(), "xterm".to_string()),
        (
            openshell_core::sandbox_env::ENDPOINT.to_string(),
            config.effective_grpc_endpoint(),
        ),
        (
            openshell_core::sandbox_env::SANDBOX_ID.to_string(),
            sandbox.id.clone(),
        ),
        (
            openshell_core::sandbox_env::SANDBOX.to_string(),
            sandbox.name.clone(),
        ),
        (
            openshell_core::sandbox_env::SSH_SOCKET_PATH.to_string(),
            config.sandbox_ssh_socket_path.clone(),
        ),
        (
            openshell_core::sandbox_env::MAIN_PROCESS_SPEC.to_string(),
            openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(
                sandbox.spec.as_ref(),
            )
            .unwrap_or_default(),
        ),
        (
            openshell_core::sandbox_env::TELEMETRY_ENABLED.to_string(),
            openshell_core::telemetry::enabled_env_value().to_string(),
        ),
        (
            openshell_core::sandbox_env::LOG_LEVEL.to_string(),
            openshell_core::driver_utils::sandbox_log_level(sandbox, &config.log_level),
        ),
    ]);
    env
}

fn driver_owned_environment_keys() -> [&'static str; 8] {
    [
        "HOME",
        "PATH",
        "TERM",
        openshell_core::sandbox_env::ENDPOINT,
        openshell_core::sandbox_env::SANDBOX_ID,
        openshell_core::sandbox_env::SANDBOX,
        openshell_core::sandbox_env::SSH_SOCKET_PATH,
        openshell_core::sandbox_env::MAIN_PROCESS_SPEC,
    ]
}

async fn write_secret_staging_materials(
    sandbox: &DriverSandbox,
    config: &AppleContainerComputeConfig,
    launch_authentication: &openshell_core::jwt::SandboxLaunchAuthentication,
    secret_staging_base: Option<&Path>,
    reuse_boundary_address: Option<std::net::SocketAddr>,
) -> Result<AppleSecretStagingDirs, Status> {
    let root = secret_staging_dir_with_base(
        &sandbox.id,
        Some(&config.sandbox_namespace),
        secret_staging_base,
    )?;
    let supervisor_dir = root.join("supervisor");
    let channel_dir = root.join("channel");
    let channel_sandbox_dir = channel_dir.join(CHANNEL_SANDBOX_SUBDIR);
    openshell_core::paths::create_dir_restricted(&root)
        .map_err(|err| Status::internal(format!("create secret staging dir failed: {err}")))?;
    // On the creation path we reserve a free port via TcpListener::bind(0)
    // and hold the reservation until staging completes to prevent a
    // concurrent bind.  On the resume path the container already owns the
    // published port; we reuse the original address and must NOT bind.
    let boundary_address = if let Some(addr) = reuse_boundary_address {
        addr
    } else {
        let reservation = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(|err| Status::internal(format!("reserve boundary port: {err}")))?;
        reservation
            .local_addr()
            .map_err(|err| Status::internal(format!("read boundary port: {err}")))?
    };
    let result = async {
        openshell_core::paths::create_dir_restricted(&supervisor_dir).map_err(|err| {
            Status::internal(format!("create supervisor staging dir failed: {err}"))
        })?;
        openshell_core::paths::create_dir_restricted(&channel_dir)
            .map_err(|err| Status::internal(format!("create channel staging dir failed: {err}")))?;
        openshell_core::paths::create_dir_restricted(&channel_sandbox_dir).map_err(|err| {
            Status::internal(format!("create channel sandbox staging dir failed: {err}"))
        })?;

        let session_id = launch_authentication.supervisor.session_id;
        let tls = generate_sandbox_tls_material(session_id).map_err(|err| {
            Status::internal(format!("generate sandbox TLS material failed: {err}"))
        })?;

        // Use the gateway-issued runtime generation so the supervisor accepts the
        // auth bundle when validating against the runtime descriptor. Driver-side
        // generation must match `launch_authentication.supervisor.runtime_generation`.
        let generation = launch_authentication
            .supervisor
            .runtime_generation
            .to_string();
        let workload_identity = ResolvedWorkloadIdentity::new(
            DEFAULT_WORKLOAD_UID,
            DEFAULT_WORKLOAD_GID,
            Vec::new(),
            "trybox".to_string(),
            format!("{}-{generation}", sandbox.id),
        )
        .map_err(|err| {
            Status::failed_precondition(format!(
                "apple-container workload identity rejected: {err}"
            ))
        })?;
        // TLS authentication is shared across all upstream transport variants.
        let transport = SandboxTransport::Tcp {
            authority: boundary_address.to_string(),
            addresses: vec![boundary_address],
        };
        // PID 1 installs a default-deny IPv4/IPv6 firewall before it execs the
        // capability-free boundary. Only loopback and replies to inbound control
        // connections can leave the guest; workload egress uses the supervisor.
        let native_evidence: Vec<u8> = serde_json::to_vec(&serde_json::json!({
            "driver": "apple-container",
            "sandbox_id": &sandbox.id,
            "generation": &generation,
            "transport": "tls-tcp",
            "egress": "guest-ipv4-ipv6-default-deny",
        }))
        .map_err(|err| {
            Status::internal(format!("encode apple outer-fence evidence failed: {err}"))
        })?;
        let outer_fence = OuterFenceGuarantees::from_enforcement_evidence(
            generation.clone(),
            [
                OuterFenceGuarantee::DefaultDenyEgress,
                OuterFenceGuarantee::NoUnmanagedEgressPath,
                OuterFenceGuarantee::RevocationVerified,
                OuterFenceGuarantee::ControllerLossFailsClosed,
            ],
            &native_evidence,
        )
        .map_err(|err| {
            Status::failed_precondition(format!(
                "apple-container outer fence projection rejected: {err}"
            ))
        })?;
        let descriptor = SandboxRuntimeDescriptor {
            boundary_id: sandbox.id.clone(),
            generation: generation.clone(),
            session_id,
            workload_identity: workload_identity.clone(),
            transport,
            tls: SandboxTlsClientConfig {
                server_name: tls.server_name.clone(),
                trust_anchor_pem: tls.trust_anchor_pem.clone(),
            },
            host_gateway_ip: None,
            resource_claims: BTreeMap::new(),
            outer_fence: outer_fence.clone(),
        };
        let verification_keys = launch_authentication
            .verification_keys
            .iter()
            .map(|key| {
                String::from_utf8(key.public_key_pem.clone())
                    .map(|public_key_pem| GatewayVerificationKey {
                        key_id: key.key_id.clone(),
                        public_key_pem,
                    })
                    .map_err(|err| {
                        Status::internal(format!(
                            "decode gateway verification key {}: {err}",
                            key.key_id
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let listener = BoundaryListener::TlsTcp {
            address: SocketAddr::from(([0, 0, 0, 0], BOUNDARY_PORT)),
            tls: SandboxTlsServerConfig {
                certificate_chain_path: PathBuf::from(format!(
                    "{CHANNEL_RUNTIME_DIR}/{TLS_SERVER_CERT_FILE}"
                )),
                private_key_path: PathBuf::from(format!(
                    "{CHANNEL_RUNTIME_DIR}/{TLS_SERVER_KEY_FILE}"
                )),
            },
        };
        let bootstrap = BoundaryConfig {
            boundary_id: sandbox.id.clone(),
            generation,
            session_id,
            session_rotation: launch_authentication.supervisor.session_rotation,
            auth_epoch: launch_authentication.supervisor.auth_epoch,
            gateway_id: launch_authentication.gateway_id.clone(),
            verification_keys,
            listener,
            resource_claims: BTreeMap::new(),
            resource_claim_files: BTreeMap::new(),
            workload_identity,
            outer_fence,
            child_env: HashMap::new(),
        };

        write_owner_only_file_bytes(
            &supervisor_dir.join(AUTH_BUNDLE_FILE),
            &serde_json::to_vec(&launch_authentication.supervisor).map_err(|err| {
                Status::internal(format!("encode supervisor auth bundle failed: {err}"))
            })?,
        )
        .await?;
        write_owner_only_file_bytes(
            &supervisor_dir.join(BACKEND_DESCRIPTOR_FILE),
            &serde_json::to_vec(&descriptor).map_err(|err| {
                Status::internal(format!("encode backend descriptor failed: {err}"))
            })?,
        )
        .await?;
        write_owner_only_file_bytes(
            &channel_sandbox_dir.join(BOOTSTRAP_FILE),
            &serde_json::to_vec(&bootstrap).map_err(|err| {
                Status::internal(format!("encode sandbox bootstrap failed: {err}"))
            })?,
        )
        .await?;
        write_owner_only_file_bytes(
            &channel_sandbox_dir.join(TLS_SERVER_CERT_FILE),
            tls.certificate_chain_pem.as_bytes(),
        )
        .await?;
        write_owner_only_file_bytes(
            &channel_sandbox_dir.join(TLS_SERVER_KEY_FILE),
            tls.private_key_pem.as_bytes(),
        )
        .await?;
        Ok::<(), Status>(())
    }
    .await;
    if let Err(err) = result {
        let _ = std::fs::remove_dir_all(&root);
        return Err(err);
    }
    Ok(AppleSecretStagingDirs {
        channel_mount_dir: channel_dir,
        boundary_host_port: boundary_address.port(),
    })
}

fn decode_launch_authentication(
    sandbox: &DriverSandbox,
) -> Result<openshell_core::jwt::SandboxLaunchAuthentication, Status> {
    let bytes = &sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox.spec is required"))?
        .launch_authentication;
    if bytes.is_empty() {
        return Err(Status::failed_precondition(
            "apple-container sandboxes require gateway launch authentication; configure [openshell.gateway.gateway_jwt]",
        ));
    }
    let auth: openshell_core::jwt::SandboxLaunchAuthentication = serde_json::from_slice(bytes)
        .map_err(|err| {
            Status::invalid_argument(format!(
                "decode apple-container launch authentication failed: {err}"
            ))
        })?;
    auth.validate().map_err(|err| {
        Status::invalid_argument(format!(
            "validate apple-container launch authentication failed: {err}"
        ))
    })?;
    Ok(auth)
}

async fn write_owner_only_file_bytes(path: &Path, contents: &[u8]) -> Result<(), Status> {
    let path = path.to_path_buf();
    let contents = contents.to_vec();
    tokio::task::spawn_blocking(move || write_owner_only_file_blocking(&path, &contents))
        .await
        .map_err(|err| Status::internal(format!("write auth file task failed: {err}")))?
}

fn write_owner_only_file_blocking(path: &Path, contents: &[u8]) -> Result<(), Status> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| Status::internal(format!("create {} failed: {err}", path.display())))?;
    file.write_all(contents)
        .map_err(|err| Status::internal(format!("write {} failed: {err}", path.display())))?;
    openshell_core::paths::set_file_owner_only(path)
        .map_err(|err| Status::internal(format!("restrict {} failed: {err}", path.display())))
}

fn cleanup_secret_staging_dir(sandbox_id: &str, config: &AppleContainerComputeConfig) {
    let Ok(dir) = secret_staging_dir(sandbox_id, Some(&config.sandbox_namespace)) else {
        return;
    };
    if let Err(err) = std::fs::remove_dir_all(&dir)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        warn!(path = %dir.display(), error = %err, "failed to remove Apple container secret staging dir");
    }
}

fn secret_staging_dir(sandbox_id: &str, namespace: Option<&str>) -> Result<PathBuf, Status> {
    secret_staging_dir_with_base(sandbox_id, namespace, None)
}

fn secret_staging_dir_with_base(
    sandbox_id: &str,
    namespace: Option<&str>,
    base: Option<&Path>,
) -> Result<PathBuf, Status> {
    let mut path = if let Some(base) = base {
        base.to_path_buf()
    } else {
        openshell_core::paths::xdg_state_dir()
            .map_err(|err| Status::internal(format!("resolve state dir failed: {err}")))?
            .join("openshell")
            .join("apple-container-secrets")
    };
    if let Some(namespace) = namespace {
        path = path.join(namespace.replace(['/', '\\'], "-"));
    }
    Ok(path.join(sandbox_id))
}

fn supervisor_bin_dir(configured: &Path) -> Result<PathBuf, Status> {
    let path = if configured.as_os_str().is_empty() {
        default_supervisor_bin_dir().ok_or_else(|| {
            Status::failed_precondition(
                "apple-container driver requires supervisor_bin_dir or OPENSHELL_APPLE_CONTAINER_SUPERVISOR_BIN_DIR",
            )
        })?
    } else {
        configured.to_path_buf()
    };
    let supervisor = path.join("openshell-sandbox");
    if !supervisor.is_file() {
        return Err(Status::failed_precondition(format!(
            "openshell-sandbox supervisor not found at {}",
            supervisor.display()
        )));
    }
    Ok(path)
}

fn default_supervisor_bin_dir() -> Option<PathBuf> {
    std::env::var_os("OPENSHELL_APPLE_CONTAINER_SUPERVISOR_BIN_DIR").map(PathBuf::from)
}

fn sandbox_memory_limit(sandbox: &DriverSandbox) -> Option<String> {
    let value = sandbox
        .spec
        .as_ref()?
        .template
        .as_ref()?
        .resources
        .as_ref()?
        .memory_limit
        .trim()
        .to_string();
    (!value.is_empty()).then(|| normalize_quantity_for_apple(&value))
}

fn sandbox_cpu_limit(sandbox: &DriverSandbox) -> Result<Option<String>, Status> {
    let Some(resources) = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .and_then(|template| template.resources.as_ref())
    else {
        return Ok(None);
    };
    normalize_cpu_for_apple(&resources.cpu_limit)
}

fn normalize_cpu_for_apple(value: &str) -> Result<Option<String>, Status> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if let Some(millicores) = value.strip_suffix('m') {
        let millicores = millicores.parse::<u64>().map_err(|_| {
            Status::failed_precondition(format!(
                "invalid apple-container cpu_limit '{value}'; expected a positive whole-core or whole-millicore quantity",
            ))
        })?;
        if millicores == 0 {
            return Err(Status::failed_precondition(
                "apple-container cpu_limit must be greater than zero",
            ));
        }
        if millicores % 1_000 != 0 {
            return Err(Status::failed_precondition(
                "apple-container cpu_limit must resolve to a whole CPU count because the Apple Container CLI expects an integer --cpus value",
            ));
        }
        return Ok(Some((millicores / 1_000).to_string()));
    }

    let cores = value.parse::<u64>().map_err(|_| {
        Status::failed_precondition(format!(
            "invalid apple-container cpu_limit '{value}'; expected a positive whole-core or whole-millicore quantity",
        ))
    })?;
    if cores == 0 {
        return Err(Status::failed_precondition(
            "apple-container cpu_limit must be greater than zero",
        ));
    }
    Ok(Some(value.to_string()))
}

fn normalize_quantity_for_apple(value: &str) -> String {
    value
        .strip_suffix("Ki")
        .map(|v| format!("{v}K"))
        .or_else(|| value.strip_suffix("Mi").map(|v| format!("{v}M")))
        .or_else(|| value.strip_suffix("Gi").map(|v| format!("{v}G")))
        .or_else(|| value.strip_suffix("Ti").map(|v| format!("{v}T")))
        .unwrap_or_else(|| value.to_string())
}

fn managed_entry(entry: &AppleContainerListEntry, config: &AppleContainerComputeConfig) -> bool {
    let labels = &entry.configuration.labels;
    labels
        .get(LABEL_MANAGED_BY)
        .is_some_and(|value| value == LABEL_MANAGED_BY_VALUE)
        && labels
            .get(LABEL_SANDBOX_NAMESPACE)
            .is_some_and(|value| value == &config.sandbox_namespace)
}

fn entry_matches(entry: &AppleContainerListEntry, sandbox_id: &str, sandbox_name: &str) -> bool {
    let labels = &entry.configuration.labels;
    let id_matches = sandbox_id.is_empty()
        || labels
            .get(LABEL_SANDBOX_ID)
            .is_some_and(|value| value == sandbox_id);
    let name_matches = sandbox_name.is_empty()
        || labels
            .get(LABEL_SANDBOX_NAME)
            .is_some_and(|value| value == sandbox_name);
    id_matches && name_matches
}

fn require_sandbox_identifier(sandbox_id: &str, sandbox_name: &str) -> Result<(), Status> {
    if sandbox_id.is_empty() && sandbox_name.is_empty() {
        return Err(Status::invalid_argument(
            "sandbox_id or sandbox_name is required",
        ));
    }
    Ok(())
}

fn driver_sandbox_from_entry(
    entry: AppleContainerListEntry,
    readiness: &dyn SupervisorReadiness,
) -> Option<DriverSandbox> {
    let labels = &entry.configuration.labels;
    let id = labels.get(LABEL_SANDBOX_ID)?.clone();
    let name = labels.get(LABEL_SANDBOX_NAME)?.clone();
    let namespace = labels
        .get(LABEL_SANDBOX_NAMESPACE)
        .cloned()
        .unwrap_or_default();
    let image = entry
        .configuration
        .image
        .as_ref()
        .map(|image| image.reference.clone())
        .unwrap_or_default();
    let supervisor_connected = readiness.is_supervisor_connected(&id);
    Some(DriverSandbox {
        id,
        name: name.clone(),
        namespace,
        spec: None,
        status: Some(DriverSandboxStatus {
            name,
            instance_id: entry.id,
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![condition_from_state(
                &entry.status.state,
                &image,
                supervisor_connected,
                entry.configuration.creation_date.as_deref(),
            )],
            deleting: apple_container_is_deleting(&entry.status.state),
            resolved_identity: None,
            fence_evidence: None,
        }),
        workspace: String::new(),
    })
}

fn condition_from_state(
    state: &str,
    image: &str,
    supervisor_connected: bool,
    creation_date: Option<&str>,
) -> DriverCondition {
    let launch_age_ms = creation_date.and_then(creation_age_ms);
    match state {
        "running" if supervisor_connected => DriverCondition {
            r#type: "Ready".to_string(),
            status: "True".to_string(),
            reason: "SupervisorConnected".to_string(),
            message: "Supervisor relay is live".to_string(),
            transition_time: None,
        },
        "running" => DriverCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: "DependenciesNotReady".to_string(),
            message: format!(
                "Apple container is running from {image}; waiting for supervisor relay"
            ),
            transition_time: None,
        },
        "created" => DriverCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: "Starting".to_string(),
            message: "Apple container is created".to_string(),
            transition_time: None,
        },
        "stopped"
            if launch_age_ms.is_some_and(|age_ms| age_ms <= TRANSIENT_STOPPED_LAUNCH_GRACE_MS) =>
        {
            DriverCondition {
                r#type: "Ready".to_string(),
                status: "False".to_string(),
                reason: "Starting".to_string(),
                message: "Apple container is starting".to_string(),
                transition_time: None,
            }
        }
        "stopped" | "exited" => DriverCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: "ContainerStopped".to_string(),
            message: "Apple container is stopped".to_string(),
            transition_time: None,
        },
        "deleting" | "removing" => DriverCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: "Deleting".to_string(),
            message: "Apple container is being removed".to_string(),
            transition_time: None,
        },
        other => DriverCondition {
            r#type: "Ready".to_string(),
            status: "Unknown".to_string(),
            reason: "ContainerStateUnknown".to_string(),
            message: format!("Apple container state is {other}"),
            transition_time: None,
        },
    }
}

fn creation_age_ms(creation_date: &str) -> Option<i64> {
    let created_at = chrono::DateTime::parse_from_rfc3339(creation_date).ok()?;
    Some(
        openshell_core::time::now_ms()
            .saturating_sub(created_at.timestamp_millis())
            .max(0),
    )
}

fn apple_container_is_deleting(state: &str) -> bool {
    matches!(state, "deleting" | "removing")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{AppleContainerConfiguration, AppleContainerImage, AppleContainerStatus};
    use openshell_core::proto::compute::v1::{
        DriverResourceRequirements, DriverSandboxSpec, DriverSandboxTemplate,
    };

    struct AlwaysReady;

    impl SupervisorReadiness for AlwaysReady {
        fn is_supervisor_connected(&self, _sandbox_id: &str) -> bool {
            true
        }
    }

    struct NeverReady;

    impl SupervisorReadiness for NeverReady {
        fn is_supervisor_connected(&self, _sandbox_id: &str) -> bool {
            false
        }
    }

    fn test_supervisor_dir(test_name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "openshell-apple-container-{test_name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn seed_test_supervisor_dir(test_name: &str) -> PathBuf {
        let dir = test_supervisor_dir(test_name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("openshell-sandbox"), b"fake supervisor").unwrap();
        std::fs::write(dir.join("trybox-entrypoint"), b"fake entrypoint").unwrap();
        dir
    }

    fn test_launch_authentication() -> Vec<u8> {
        use openshell_core::jwt::{
            CredentialEpoch, SandboxLaunchAuthentication, SecretJwt, SessionVerificationKey,
            SupervisorAuthBundle,
        };
        serde_json::to_vec(&SandboxLaunchAuthentication {
            supervisor: SupervisorAuthBundle {
                session_id: openshell_core::SandboxSessionId::new(),
                runtime_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
                    "generation-1",
                )
                .unwrap(),
                session_rotation: openshell_core::jwt::SessionRotation::new(1).unwrap(),
                auth_epoch: CredentialEpoch::new(1).unwrap(),
                gateway_token: SecretJwt::parse("gateway.token.value").unwrap(),
                gateway_expires_at: i64::MAX,
                sandbox_token: SecretJwt::parse("sandbox.token.value").unwrap(),
                sandbox_expires_at: i64::MAX,
            },
            gateway_id: "gateway-test".to_string(),
            verification_keys: vec![SessionVerificationKey {
                key_id: "test-key".to_string(),
                public_key_pem: b"public-key".to_vec(),
            }],
        })
        .unwrap()
    }

    #[test]
    fn container_name_sanitizes_unsupported_characters() {
        let sandbox = DriverSandbox {
            id: "sbx/id".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            workspace: String::new(),
            spec: None,
            status: None,
        };
        assert_eq!(
            container_name_for_sandbox(&sandbox),
            "openshell-sandbox-demo-sbx-id"
        );
    }

    #[test]
    fn container_name_preserves_id_suffix_with_apple_length_limit() {
        let sandbox = DriverSandbox {
            id: "d40fd9e4-39be-4182-b0bf-54c295292dca".to_string(),
            name: "hermes-apple-e2e-mainbase".to_string(),
            namespace: String::new(),
            workspace: String::new(),
            spec: None,
            status: None,
        };

        let name = container_name_for_sandbox(&sandbox);

        assert_eq!(name.len(), MAX_CONTAINER_NAME_LEN);
        assert!(name.ends_with("d40fd9e4-39be-4182-b0bf-54c295292dca"));
    }

    #[test]
    fn volume_name_uses_sandbox_id() {
        assert_eq!(
            volume_name("sandbox/id"),
            "openshell-sandbox-sandbox-id".to_string()
        );
    }

    #[test]
    fn condition_maps_running_to_waiting_until_supervisor_connects() {
        let condition = condition_from_state("running", "example:latest", false, None);
        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, "DependenciesNotReady");
    }

    #[test]
    fn condition_maps_connected_supervisor_to_ready() {
        let condition = condition_from_state("running", "example:latest", true, None);
        assert_eq!(condition.status, "True");
        assert_eq!(condition.reason, "SupervisorConnected");
    }

    #[test]
    fn condition_maps_recent_stopped_container_to_starting() {
        let recent_creation_date = rfc3339_from_unix_ms(openshell_core::time::now_ms() - 1_000);

        let condition = condition_from_state(
            "stopped",
            "example:latest",
            false,
            Some(&recent_creation_date),
        );

        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, "Starting");
    }

    #[test]
    fn condition_maps_old_stopped_container_to_terminal_error() {
        let old_creation_date = rfc3339_from_unix_ms(
            openshell_core::time::now_ms() - TRANSIENT_STOPPED_LAUNCH_GRACE_MS - 1_000,
        );

        let condition =
            condition_from_state("stopped", "example:latest", false, Some(&old_creation_date));

        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, "ContainerStopped");
    }

    #[test]
    fn memory_quantity_maps_kubernetes_suffixes() {
        assert_eq!(normalize_quantity_for_apple("512Mi"), "512M");
        assert_eq!(normalize_quantity_for_apple("4Gi"), "4G");
    }

    #[test]
    fn cpu_limit_reads_typed_resources() {
        let sandbox = DriverSandbox {
            id: "id".to_string(),
            name: "name".to_string(),
            namespace: String::new(),
            workspace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate {
                    resources: Some(DriverResourceRequirements {
                        cpu_limit: "2".to_string(),
                        ..DriverResourceRequirements::default()
                    }),
                    ..DriverSandboxTemplate::default()
                }),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };
        assert_eq!(sandbox_cpu_limit(&sandbox).unwrap().as_deref(), Some("2"));
    }

    #[test]
    fn cpu_limit_accepts_whole_core_quantities_for_apple_cli() {
        assert_eq!(
            normalize_cpu_for_apple("2000m").unwrap().as_deref(),
            Some("2")
        );
        assert_eq!(normalize_cpu_for_apple("2").unwrap().as_deref(), Some("2"));
    }

    #[test]
    fn cpu_limit_rejects_fractional_values_for_apple_cli() {
        let err = normalize_cpu_for_apple("500m").unwrap_err();
        assert_eq!(
            err.message(),
            "apple-container cpu_limit must resolve to a whole CPU count because the Apple Container CLI expects an integer --cpus value"
        );

        let err = normalize_cpu_for_apple("1.5").unwrap_err();
        assert!(
            err.message()
                .contains("expected a positive whole-core or whole-millicore quantity")
        );
    }

    #[test]
    fn cpu_limit_rejects_non_positive_values() {
        let err = normalize_cpu_for_apple("0").unwrap_err();
        assert_eq!(
            err.message(),
            "apple-container cpu_limit must be greater than zero"
        );

        let err = normalize_cpu_for_apple("0m").unwrap_err();
        assert_eq!(
            err.message(),
            "apple-container cpu_limit must be greater than zero"
        );
    }

    fn network_entry(id: &str, name: &str, gateway: Option<&str>) -> AppleContainerNetworkEntry {
        AppleContainerNetworkEntry {
            id: id.to_string(),
            configuration: crate::cli::AppleContainerNetworkConfiguration {
                name: name.to_string(),
            },
            status: crate::cli::AppleContainerNetworkStatus {
                ipv4_gateway: gateway.map(|value| value.parse().unwrap()),
            },
        }
    }

    #[test]
    fn apple_default_network_gateway_prefers_default_network() {
        let networks = vec![
            network_entry("other", "other", Some("192.168.100.1")),
            network_entry("default", "default", Some("192.168.64.1")),
        ];

        assert_eq!(
            apple_default_network_gateway(&networks).map(|ip| ip.to_string()),
            Some("192.168.64.1".to_string())
        );
    }

    #[test]
    fn apple_default_network_gateway_falls_back_to_first_gateway() {
        let networks = vec![
            network_entry("default", "default", None),
            network_entry("custom", "custom", Some("192.168.127.1")),
        ];

        assert_eq!(
            apple_default_network_gateway(&networks).map(|ip| ip.to_string()),
            Some("192.168.127.1".to_string())
        );
    }

    #[test]
    fn lifecycle_state_predicates_match_startable_and_stoppable_states() {
        for state in ["created", "stopped", "exited"] {
            assert!(
                apple_container_state_needs_resume(state),
                "{state} should be resumed"
            );
        }
        for state in ["running", "deleting", "removing", "unknown"] {
            assert!(
                !apple_container_state_needs_resume(state),
                "{state} should not be resumed"
            );
        }
        for state in ["created", "running"] {
            assert!(
                apple_container_state_needs_shutdown_stop(state),
                "{state} should be stopped on shutdown"
            );
        }
        for state in ["stopped", "exited", "deleting", "removing", "unknown"] {
            assert!(
                !apple_container_state_needs_shutdown_stop(state),
                "{state} should not be stopped on shutdown"
            );
        }
    }

    #[test]
    fn default_endpoint_uses_apple_host_dns_name() {
        let config = AppleContainerComputeConfig {
            gateway_port: 17686,
            ..AppleContainerComputeConfig::default()
        };

        assert_eq!(
            config.effective_grpc_endpoint(),
            "http://host.container.internal:17686"
        );
    }

    #[test]
    fn default_endpoint_uses_https_when_guest_tls_is_configured() {
        let config = AppleContainerComputeConfig {
            gateway_port: 17686,
            guest_tls_ca: Some(PathBuf::from("/host/ca.crt")),
            guest_tls_cert: Some(PathBuf::from("/host/tls.crt")),
            guest_tls_key: Some(PathBuf::from("/host/tls.key")),
            ..AppleContainerComputeConfig::default()
        };

        assert_eq!(
            config.effective_grpc_endpoint(),
            "https://host.container.internal:17686"
        );
    }

    #[test]
    fn sandbox_environment_preserves_driver_owned_values() {
        let mut spec_env = std::collections::HashMap::new();
        spec_env.insert(
            openshell_core::sandbox_env::ENDPOINT.to_string(),
            "http://attacker.invalid".to_string(),
        );
        spec_env.insert(
            openshell_core::sandbox_env::SANDBOX_TOKEN_FILE.to_string(),
            "/tmp/attacker-token".to_string(),
        );
        spec_env.insert(
            openshell_core::sandbox_env::SANDBOX_TOKEN.to_string(),
            "inline-secret".to_string(),
        );
        spec_env.insert(
            openshell_core::sandbox_env::TLS_CA.to_string(),
            "/tmp/user-ca.crt".to_string(),
        );
        spec_env.insert("VISIBLE".to_string(), "value".to_string());
        spec_env.insert(
            openshell_core::sandbox_env::USER_ENVIRONMENT.to_string(),
            "{\"ATTACK\":\"1\"}".to_string(),
        );
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            workspace: String::new(),
            spec: Some(DriverSandboxSpec {
                environment: spec_env,
                sandbox_token: "gateway-token".to_string(),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        let env = sandbox_environment(&sandbox, &AppleContainerComputeConfig::default());

        assert_eq!(
            env.get(openshell_core::sandbox_env::ENDPOINT)
                .map(String::as_str),
            Some("http://host.container.internal:17670")
        );
        assert!(!env.contains_key(openshell_core::sandbox_env::SANDBOX_TOKEN));
        assert!(!env.contains_key(openshell_core::sandbox_env::SANDBOX_TOKEN_FILE));
        assert!(!env.contains_key(openshell_core::sandbox_env::TLS_CA));
        assert_eq!(env.get("VISIBLE").map(String::as_str), Some("value"));
        let user_env_json = env
            .get(openshell_core::sandbox_env::USER_ENVIRONMENT)
            .expect("user environment JSON should be set");
        let user_env: BTreeMap<String, String> = serde_json::from_str(user_env_json).unwrap();
        assert_eq!(user_env.get("VISIBLE").map(String::as_str), Some("value"));
        assert!(!user_env.contains_key(openshell_core::sandbox_env::ENDPOINT));
        assert!(!user_env.contains_key(openshell_core::sandbox_env::USER_ENVIRONMENT));
        assert!(!user_env.contains_key(openshell_core::sandbox_env::TLS_CA));
    }

    #[test]
    fn require_sandbox_identifier_rejects_empty_target() {
        let err = require_sandbox_identifier("", "").unwrap_err();
        assert_eq!(err.message(), "sandbox_id or sandbox_name is required");
        assert!(require_sandbox_identifier("sbx-1", "").is_ok());
        assert!(require_sandbox_identifier("", "demo").is_ok());
    }

    #[tokio::test]
    async fn create_args_force_supervisor_to_run_as_root() {
        let tempdir = seed_test_supervisor_dir("root-supervisor");
        std::fs::create_dir_all(&tempdir).unwrap();
        std::fs::write(tempdir.join("openshell-sandbox"), b"fake supervisor").unwrap();
        let driver = AppleContainerComputeDriver {
            cli: AppleContainerCli::new(PathBuf::from("container")),
            config: AppleContainerComputeConfig {
                supervisor_bin_dir: tempdir.clone(),
                ..AppleContainerComputeConfig::default()
            },
            gateway_bind_addresses: Vec::new(),
            supervisor_readiness: Arc::new(NeverReady),
            events: broadcast::channel(WATCH_BUFFER).0,
            supervisor_children: Arc::new(
                tokio::sync::Mutex::new(std::collections::HashMap::new()),
            ),
        };
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            workspace: String::new(),
            spec: Some(DriverSandboxSpec {
                launch_authentication: test_launch_authentication(),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        let args = driver
            .create_args_with_secret_staging_base(&sandbox, Some(&tempdir))
            .await
            .unwrap();

        assert_eq!(arg_value(&args, "--user"), Some("0:0"));
        let published = arg_value(&args, "--publish").unwrap();
        assert!(published.starts_with("127.0.0.1:"));
        assert!(published.ends_with(":17672"));
        let root = tempdir.join("default/sbx-1");
        let descriptor: SandboxRuntimeDescriptor = serde_json::from_slice(
            &std::fs::read(root.join("supervisor/backend-descriptor.json")).unwrap(),
        )
        .unwrap();
        let bootstrap: BoundaryConfig = serde_json::from_slice(
            &std::fs::read(root.join("channel/sandbox/bootstrap.json")).unwrap(),
        )
        .unwrap();
        match descriptor.transport {
            SandboxTransport::Tcp { addresses, .. } => {
                assert_eq!(addresses.len(), 1);
                assert_eq!(published, format!("{}:17672", addresses[0]));
            }
            _ => panic!("host-to-guest sockets cannot use virtiofs"),
        }
        match bootstrap.listener {
            BoundaryListener::TlsTcp { address, tls } => {
                assert_eq!(address.port(), BOUNDARY_PORT);
                assert!(tls.private_key_path.starts_with(CHANNEL_RUNTIME_DIR));
            }
            _ => panic!("boundary must use authenticated TCP"),
        }
        let mounts = arg_values(&args, "--mount");
        assert!(
            mounts
                .iter()
                .all(|mount| !mount.contains("target=/.openshell/supervisor"))
        );
        assert!(mounts.iter().any(
            |mount| mount.contains("target=/.openshell/channel") && mount.contains("readonly")
        ));
        std::fs::remove_dir_all(tempdir).unwrap();
    }

    #[tokio::test]
    async fn create_args_merges_template_labels_with_managed_labels() {
        let tempdir = seed_test_supervisor_dir("container-labels");
        std::fs::create_dir_all(&tempdir).unwrap();
        std::fs::write(tempdir.join("openshell-sandbox"), b"fake supervisor").unwrap();
        let driver = AppleContainerComputeDriver {
            cli: AppleContainerCli::new(PathBuf::from("container")),
            config: AppleContainerComputeConfig {
                supervisor_bin_dir: tempdir.clone(),
                sandbox_namespace: "team-a".to_string(),
                ..AppleContainerComputeConfig::default()
            },
            gateway_bind_addresses: Vec::new(),
            supervisor_readiness: Arc::new(NeverReady),
            events: broadcast::channel(WATCH_BUFFER).0,
            supervisor_children: Arc::new(
                tokio::sync::Mutex::new(std::collections::HashMap::new()),
            ),
        };
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            workspace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate {
                    labels: std::collections::HashMap::from([
                        ("custom.example/role".to_string(), "worker".to_string()),
                        (LABEL_SANDBOX_ID.to_string(), "spoofed".to_string()),
                    ]),
                    ..DriverSandboxTemplate::default()
                }),
                launch_authentication: test_launch_authentication(),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        let args = driver
            .create_args_with_secret_staging_base(&sandbox, Some(&tempdir))
            .await
            .unwrap();
        let labels = arg_values(&args, "--label");

        assert!(labels.contains(&"custom.example/role=worker"));
        assert!(labels.contains(&"openshell.ai/sandbox-id=sbx-1"));
        assert!(labels.contains(&"openshell.ai/sandbox-name=demo"));
        assert!(labels.contains(&"openshell.ai/sandbox-namespace=team-a"));
        assert!(!labels.contains(&"openshell.ai/sandbox-id=spoofed"));
        std::fs::remove_dir_all(tempdir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn create_args_overrides_image_cmd_with_supervisor_command() {
        let tempdir = seed_test_supervisor_dir("supervisor-command");
        std::fs::create_dir_all(&tempdir).unwrap();
        std::fs::write(tempdir.join("openshell-sandbox"), b"fake supervisor").unwrap();
        let driver = AppleContainerComputeDriver {
            cli: AppleContainerCli::new(PathBuf::from("container")),
            config: AppleContainerComputeConfig {
                supervisor_bin_dir: tempdir.clone(),
                default_image: "example/image:latest".to_string(),
                ..AppleContainerComputeConfig::default()
            },
            gateway_bind_addresses: Vec::new(),
            supervisor_readiness: Arc::new(NeverReady),
            events: broadcast::channel(WATCH_BUFFER).0,
            supervisor_children: Arc::new(
                tokio::sync::Mutex::new(std::collections::HashMap::new()),
            ),
        };
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            workspace: String::new(),
            spec: Some(DriverSandboxSpec {
                launch_authentication: test_launch_authentication(),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        let args = driver
            .create_args_with_secret_staging_base(&sandbox, Some(&tempdir))
            .await
            .unwrap();

        // Modern entrypoint contract: /opt/openshell/bin/trybox-entrypoint with NO
        // `sleep infinity` tail. The image arg appears as the final token.
        assert_eq!(
            args.last().map(String::as_str),
            Some("example/image:latest")
        );
        assert!(!args.iter().any(|arg| arg == "sleep"));
        assert!(!args.iter().any(|arg| arg == "infinity"));
        assert!(
            args.contains(&format!(
                "--entrypoint=/opt/openshell/bin/trybox-entrypoint"
            )) || args.contains(&"--entrypoint".to_string())
        );
        std::fs::remove_dir_all(tempdir).unwrap();
    }

    #[test]
    fn validate_sandbox_create_accepts_sanitized_runtime_names() {
        let tempdir = seed_test_supervisor_dir("validate-sanitized-name");
        std::fs::create_dir_all(&tempdir).unwrap();
        let driver = AppleContainerComputeDriver {
            cli: AppleContainerCli::new(PathBuf::from("container")),
            config: AppleContainerComputeConfig {
                supervisor_bin_dir: tempdir.clone(),
                ..AppleContainerComputeConfig::default()
            },
            gateway_bind_addresses: Vec::new(),
            supervisor_readiness: Arc::new(NeverReady),
            events: broadcast::channel(WATCH_BUFFER).0,
            supervisor_children: Arc::new(
                tokio::sync::Mutex::new(std::collections::HashMap::new()),
            ),
        };
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo/name".to_string(),
            namespace: String::new(),
            workspace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate::default()),
                sandbox_token: "token".to_string(),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        driver.validate_sandbox_create(&sandbox).unwrap();
        assert_eq!(
            container_name_for_sandbox(&sandbox),
            "openshell-sandbox-demo-name-sbx-1"
        );
        std::fs::remove_dir_all(tempdir).unwrap();
    }

    #[test]
    fn validate_sandbox_create_allows_missing_sandbox_token_for_preflight() {
        let tempdir = seed_test_supervisor_dir("validate-auth-token");
        std::fs::create_dir_all(&tempdir).unwrap();
        let driver = AppleContainerComputeDriver {
            cli: AppleContainerCli::new(PathBuf::from("container")),
            config: AppleContainerComputeConfig {
                supervisor_bin_dir: tempdir.clone(),
                ..AppleContainerComputeConfig::default()
            },
            gateway_bind_addresses: Vec::new(),
            supervisor_readiness: Arc::new(NeverReady),
            events: broadcast::channel(WATCH_BUFFER).0,
            supervisor_children: Arc::new(
                tokio::sync::Mutex::new(std::collections::HashMap::new()),
            ),
        };
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            workspace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate::default()),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        driver.validate_sandbox_create(&sandbox).unwrap();
        std::fs::remove_dir_all(tempdir).unwrap();
    }

    #[test]
    fn validate_sandbox_auth_rejects_missing_launch_authentication() {
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            workspace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate::default()),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        let err = validate_sandbox_auth(&sandbox).unwrap_err();

        assert_eq!(
            err.message(),
            "apple-container sandboxes require gateway launch authentication; configure [openshell.gateway.gateway_jwt]"
        );
    }

    #[test]
    fn validate_sandbox_create_rejects_missing_image_sources() {
        let tempdir = seed_test_supervisor_dir("validate-image");
        std::fs::create_dir_all(&tempdir).unwrap();
        let driver = AppleContainerComputeDriver {
            cli: AppleContainerCli::new(PathBuf::from("container")),
            config: AppleContainerComputeConfig {
                supervisor_bin_dir: tempdir.clone(),
                default_image: String::new(),
                ..AppleContainerComputeConfig::default()
            },
            gateway_bind_addresses: Vec::new(),
            supervisor_readiness: Arc::new(NeverReady),
            events: broadcast::channel(WATCH_BUFFER).0,
            supervisor_children: Arc::new(
                tokio::sync::Mutex::new(std::collections::HashMap::new()),
            ),
        };
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            workspace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate::default()),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        let err = driver.validate_sandbox_create(&sandbox).unwrap_err();

        assert!(
            err.message()
                .contains("no sandbox image configured: set default_image")
        );
        std::fs::remove_dir_all(tempdir).unwrap();
    }

    #[test]
    fn validate_sandbox_template_rejects_driver_config() {
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            workspace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate {
                    driver_config: Some(prost_types::Struct {
                        fields: BTreeMap::from([(
                            "mounts".to_string(),
                            prost_types::Value {
                                kind: Some(prost_types::value::Kind::ListValue(
                                    prost_types::ListValue { values: Vec::new() },
                                )),
                            },
                        )]),
                    }),
                    ..DriverSandboxTemplate::default()
                }),
                sandbox_token: "token".to_string(),
                ..DriverSandboxSpec::default()
            }),
            status: None,
        };

        let err = validate_sandbox_template(&sandbox).unwrap_err();

        assert_eq!(
            err.message(),
            "apple-container compute driver does not support template.driver_config"
        );
    }

    #[test]
    fn watch_event_cache_applies_sandbox_and_delete_events() {
        let sandbox = DriverSandbox {
            id: "sbx-1".to_string(),
            name: "demo".to_string(),
            namespace: "default".to_string(),
            workspace: String::new(),
            spec: None,
            status: None,
        };
        let mut cache = BTreeMap::new();

        apply_watch_event_to_cache(&mut cache, &watch_sandbox_event(sandbox.clone()));
        assert_eq!(cache.get("sbx-1"), Some(&sandbox));

        apply_watch_event_to_cache(&mut cache, &watch_deleted_event("sbx-1".to_string()));
        assert!(!cache.contains_key("sbx-1"));
    }

    #[test]
    fn managed_entry_requires_matching_namespace() {
        let config = AppleContainerComputeConfig {
            sandbox_namespace: "team-a".to_string(),
            ..AppleContainerComputeConfig::default()
        };
        let entry = list_entry("sbx-1", "demo", "team-a", "running");
        assert!(managed_entry(&entry, &config));

        let other = list_entry("sbx-1", "demo", "team-b", "running");
        assert!(!managed_entry(&other, &config));
    }

    #[test]
    fn entry_matches_accepts_id_or_name() {
        let entry = list_entry("sbx-1", "demo", "default", "running");
        assert!(entry_matches(&entry, "sbx-1", ""));
        assert!(entry_matches(&entry, "", "demo"));
        assert!(entry_matches(&entry, "sbx-1", "demo"));
        assert!(!entry_matches(&entry, "sbx-2", ""));
        assert!(!entry_matches(&entry, "", "other"));
    }

    #[test]
    fn driver_sandbox_uses_supervisor_readiness() {
        let waiting = driver_sandbox_from_entry(
            list_entry("sbx-1", "demo", "default", "running"),
            &NeverReady,
        )
        .unwrap();
        let waiting_condition = &waiting.status.unwrap().conditions[0];
        assert_eq!(waiting_condition.status, "False");
        assert_eq!(waiting_condition.reason, "DependenciesNotReady");

        let ready = driver_sandbox_from_entry(
            list_entry("sbx-1", "demo", "default", "running"),
            &AlwaysReady,
        )
        .unwrap();
        let ready_condition = &ready.status.unwrap().conditions[0];
        assert_eq!(ready_condition.status, "True");
        assert_eq!(ready_condition.reason, "SupervisorConnected");
    }

    fn list_entry(
        sandbox_id: &str,
        sandbox_name: &str,
        namespace: &str,
        state: &str,
    ) -> AppleContainerListEntry {
        let labels = BTreeMap::from([
            (
                LABEL_MANAGED_BY.to_string(),
                LABEL_MANAGED_BY_VALUE.to_string(),
            ),
            (LABEL_SANDBOX_ID.to_string(), sandbox_id.to_string()),
            (LABEL_SANDBOX_NAME.to_string(), sandbox_name.to_string()),
            (LABEL_SANDBOX_NAMESPACE.to_string(), namespace.to_string()),
        ]);
        AppleContainerListEntry {
            id: format!("runtime-{sandbox_id}"),
            configuration: AppleContainerConfiguration {
                creation_date: None,
                labels,
                image: Some(AppleContainerImage {
                    reference: "example:latest".to_string(),
                }),
            },
            status: AppleContainerStatus {
                state: state.to_string(),
            },
        }
    }

    fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
        args.windows(2)
            .find(|window| window[0] == name)
            .map(|window| window[1].as_str())
    }

    fn arg_values<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
        args.windows(2)
            .filter(|window| window[0] == name)
            .map(|window| window[1].as_str())
            .collect()
    }

    fn rfc3339_from_unix_ms(unix_ms: i64) -> String {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(unix_ms)
            .unwrap()
            .to_rfc3339()
    }
}
