// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standalone Apple Container compute-driver binary.
//!
//! Serves `openshell.compute.v1.ComputeDriver` over a Unix Domain Socket so an
//! unmodified upstream `openshell-gateway` can drive Apple's `container` CLI
//! through `--compute-driver apple-container --compute-driver-socket <path>`.

use clap::Parser;
use futures::Stream;
use miette::{IntoDiagnostic, Result};
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_driver_apple_container::{
    AlwaysReadySupervisor, AppleContainerComputeConfig, AppleContainerComputeDriver,
    ComputeDriverService,
};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::{UnixListener, UnixStream};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "openshell-driver-apple-container")]
#[command(version = openshell_core::VERSION)]
#[command(about = "Apple Container compute driver for NVIDIA OpenShell (out-of-tree, UDS)")]
struct Args {
    /// Unix-domain socket path the driver serves `openshell.compute.v1.ComputeDriver` on.
    #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_SOCKET")]
    bind_socket: PathBuf,

    /// Skip the same-UID/peer-pid UDS peer check (local development only).
    #[arg(
        long,
        env = "OPENSHELL_COMPUTE_DRIVER_ALLOW_SAME_UID_PEER",
        default_value_t = false
    )]
    allow_same_uid_peer: bool,

    /// Optional gateway PID that is the only UDS peer allowed to connect.
    #[arg(long, hide = true)]
    expected_peer_pid: Option<u32>,

    /// Path to the `container` CLI (defaults to PATH lookup).
    #[arg(
        long,
        env = "OPENSHELL_APPLE_CONTAINER_BIN",
        default_value = "container"
    )]
    container_bin: PathBuf,

    /// Default OCI image for sandboxes.
    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE", default_value = "")]
    default_image: String,

    /// Logical sandbox namespace; joined into the managed-label filter.
    #[arg(
        long,
        env = "OPENSHELL_APPLE_CONTAINER_NAMESPACE",
        default_value = "default"
    )]
    sandbox_namespace: String,

    /// Full gRPC endpoint the in-guest supervisor dials. If empty the driver
    /// builds one from `--gateway-port` plus `--host-callback-host`.
    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT", default_value = "")]
    grpc_endpoint: String,

    /// Gateway listener port used when `--grpc-endpoint` is empty.
    #[arg(
        long,
        env = "OPENSHELL_GATEWAY_PORT",
        default_value_t = openshell_core::config::DEFAULT_SERVER_PORT
    )]
    gateway_port: u16,

    /// Hostname Apple container VMs use to call back to the gateway.
    #[arg(
        long,
        env = "OPENSHELL_APPLE_CONTAINER_HOST_CALLBACK_HOST",
        default_value = "host.container.internal"
    )]
    host_callback_host: String,

    /// Host path to the CA certificate for sandbox mTLS.
    #[arg(long = "guest-tls-ca", env = "OPENSHELL_APPLE_CONTAINER_TLS_CA")]
    guest_tls_ca: Option<PathBuf>,

    /// Host path to the client certificate for sandbox mTLS.
    #[arg(long = "guest-tls-cert", env = "OPENSHELL_APPLE_CONTAINER_TLS_CERT")]
    guest_tls_cert: Option<PathBuf>,

    /// Host path to the client private key for sandbox mTLS.
    #[arg(long = "guest-tls-key", env = "OPENSHELL_APPLE_CONTAINER_TLS_KEY")]
    guest_tls_key: Option<PathBuf>,

    /// Directory containing the Linux `openshell-sandbox` + `openshell-supervisor`
    /// binaries that get staged into each sandbox guest.
    #[arg(
        long,
        env = "OPENSHELL_APPLE_CONTAINER_SUPERVISOR_BIN_DIR",
        default_value = ""
    )]
    supervisor_bin_dir: PathBuf,

    /// macOS host-side supervisor binary path. Override with
    /// `OPENSHELL_APPLE_CONTAINER_HOST_SUPERVISOR_BIN`. When unset, the driver
    /// falls back to `~/.local/share/trybox/host-bin/openshell-supervisor`.
    #[arg(long, env = openshell_driver_apple_container::driver::HOST_SUPERVISOR_BIN_ENV)]
    host_supervisor_bin: Option<PathBuf>,

    /// Host-side CA bundle for mTLS when the host supervisor dials the gateway
    /// from the macOS host (the host cannot use `host.container.internal`).
    #[arg(long)]
    host_tls_ca: Option<PathBuf>,

    /// Host-side client certificate for the supervisor's mTLS handshake.
    #[arg(long)]
    host_tls_cert: Option<PathBuf>,

    /// Host-side client key for the supervisor's mTLS handshake.
    #[arg(long)]
    host_tls_key: Option<PathBuf>,

    /// Unix socket path inside the guest where the supervisor exposes SSH-relay traffic.
    #[arg(
        long,
        env = "OPENSHELL_APPLE_CONTAINER_SSH_SOCKET_PATH",
        default_value = "/run/openshell/ssh.sock"
    )]
    sandbox_ssh_socket_path: String,

    /// Container stop timeout in seconds.
    #[arg(
        long,
        env = "OPENSHELL_APPLE_CONTAINER_STOP_TIMEOUT_SECS",
        default_value_t = openshell_core::config::DEFAULT_STOP_TIMEOUT_SECS
    )]
    stop_timeout_secs: u32,

    /// Log level forwarded to the in-guest supervisor.
    #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "warn")]
    log_level: String,

    /// Driver-side log level filter.
    #[arg(long, env = "OPENSHELL_DRIVER_LOG_LEVEL", default_value = "info")]
    driver_log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.driver_log_level)),
        )
        .with_writer(std::io::stderr)
        .init();

    let config = AppleContainerComputeConfig {
        container_bin: args.container_bin.clone(),
        default_image: args.default_image.clone(),
        sandbox_namespace: args.sandbox_namespace.clone(),
        grpc_endpoint: args.grpc_endpoint.clone(),
        gateway_port: args.gateway_port,
        host_callback_host: args.host_callback_host.clone(),
        guest_tls_ca: args.guest_tls_ca.clone(),
        guest_tls_cert: args.guest_tls_cert.clone(),
        guest_tls_key: args.guest_tls_key.clone(),
        supervisor_bin_dir: args.supervisor_bin_dir.clone(),
        host_supervisor_bin: args.host_supervisor_bin.clone(),
        host_tls_ca: args.host_tls_ca.clone(),
        host_tls_cert: args.host_tls_cert.clone(),
        host_tls_key: args.host_tls_key.clone(),
        sandbox_ssh_socket_path: args.sandbox_ssh_socket_path.clone(),
        stop_timeout_secs: args.stop_timeout_secs,
        log_level: args.log_level.clone(),
    };

    let driver = AppleContainerComputeDriver::new(config, Arc::new(AlwaysReadySupervisor))
        .await
        .map_err(|err| miette::miette!("init apple-container driver: {err}"))?;

    if !args.allow_same_uid_peer && args.expected_peer_pid.is_none() {
        return Err(miette::miette!(
            "--expected-peer-pid is required; pass --allow-same-uid-peer only for local development"
        ));
    }

    prepare_compute_driver_socket(&args.bind_socket).map_err(|err| miette::miette!("{err}"))?;
    let listener = UnixListener::bind(&args.bind_socket).into_diagnostic()?;
    restrict_socket_permissions(&args.bind_socket).map_err(|err| miette::miette!("{err}"))?;

    info!(
        socket = %args.bind_socket.display(),
        "starting apple-container compute driver"
    );
    let service = ComputeDriverService::new(Arc::new(driver));
    let result = tonic::transport::Server::builder()
        .add_service(ComputeDriverServer::new(service))
        .serve_with_incoming_shutdown(
            AuthenticatedUnixIncoming::new(listener, args.expected_peer_pid),
            shutdown_signal(),
        )
        .await
        .into_diagnostic();
    let _ = std::fs::remove_file(&args.bind_socket);
    result
}

async fn shutdown_signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::warn!(%error, "failed to listen for Ctrl-C");
            }
        }
        _ = terminate.recv() => {}
    }
    info!("shutdown signal received; stopping apple-container compute driver");
}

fn current_euid() -> u32 {
    // SAFETY: geteuid is async-signal-safe and has no failure mode.
    unsafe { libc::geteuid() }
}

fn prepare_compute_driver_socket(socket_path: &Path) -> std::result::Result<(), String> {
    let Some(parent) = socket_path.parent() else {
        return Err(format!(
            "apple-container driver socket path '{}' has no parent directory",
            socket_path.display()
        ));
    };
    let expected_uid = current_euid();
    prepare_private_socket_dir(parent, expected_uid)?;
    remove_stale_socket(socket_path, expected_uid)
}

fn prepare_private_socket_dir(
    socket_dir: &Path,
    expected_uid: u32,
) -> std::result::Result<(), String> {
    std::fs::create_dir_all(socket_dir)
        .map_err(|err| format!("create socket dir {}: {err}", socket_dir.display()))?;
    let metadata = std::fs::symlink_metadata(socket_dir)
        .map_err(|err| format!("stat socket dir {}: {err}", socket_dir.display()))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(format!(
            "socket dir {} is a symlink; refusing to use it",
            socket_dir.display()
        ));
    }
    if !file_type.is_dir() {
        return Err(format!(
            "socket dir {} is not a directory",
            socket_dir.display()
        ));
    }
    if metadata.uid() != expected_uid {
        return Err(format!(
            "socket dir {} is owned by uid {} but current euid is {}",
            socket_dir.display(),
            metadata.uid(),
            expected_uid
        ));
    }
    std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("chmod socket dir {}: {err}", socket_dir.display()))
}

fn remove_stale_socket(socket_path: &Path, expected_uid: u32) -> std::result::Result<(), String> {
    let metadata = match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("stat socket {}: {err}", socket_path.display())),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(format!(
            "socket {} is a symlink; refusing to remove it",
            socket_path.display()
        ));
    }
    if metadata.uid() != expected_uid {
        return Err(format!(
            "socket {} is owned by uid {} but current euid is {}",
            socket_path.display(),
            metadata.uid(),
            expected_uid
        ));
    }
    if !file_type.is_socket() {
        return Err(format!(
            "socket path {} exists but is not a Unix socket",
            socket_path.display()
        ));
    }
    std::fs::remove_file(socket_path)
        .map_err(|err| format!("remove stale socket {}: {err}", socket_path.display()))
}

fn restrict_socket_permissions(socket_path: &Path) -> std::result::Result<(), String> {
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("chmod socket {}: {err}", socket_path.display()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerCredentials {
    uid: u32,
}

fn peer_credentials(stream: &UnixStream) -> std::result::Result<PeerCredentials, String> {
    let credentials = stream
        .peer_cred()
        .map_err(|err| format!("read peer credentials: {err}"))?;
    Ok(PeerCredentials {
        uid: credentials.uid(),
    })
}

fn authorize_peer_credentials(
    peer: PeerCredentials,
    driver_uid: u32,
) -> std::result::Result<(), String> {
    if peer.uid != driver_uid {
        return Err(format!(
            "peer uid {} does not match current euid {}",
            peer.uid, driver_uid
        ));
    }
    Ok(())
}

struct AuthenticatedUnixIncoming {
    listener: UnixListener,
    expected_uid: u32,
}

impl AuthenticatedUnixIncoming {
    fn new(listener: UnixListener, _expected_peer_pid: Option<u32>) -> Self {
        Self {
            listener,
            expected_uid: current_euid(),
        }
    }
}

impl Stream for AuthenticatedUnixIncoming {
    type Item = io::Result<UnixStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, _addr))) => {
                    let authorized = peer_credentials(&stream)
                        .and_then(|peer| authorize_peer_credentials(peer, this.expected_uid));
                    match authorized {
                        Ok(()) => return Poll::Ready(Some(Ok(stream))),
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                "rejected apple-container compute driver UDS client"
                            );
                        }
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
