// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! trybox-entrypoint — PID 1 inside each Apple Container sandbox guest.
//!
//! Spawns the guest boundary only: the host driver owns the supervisor process.
//!
//! Flow:
//!   1. Verify the staged files at /.openshell/channel/sandbox/.
//!   2. Spawn `/opt/openshell/bin/openshell-sandbox launch-capability-free <UID> <GID> <BOOTSTRAP>`.
//!      The launch-capability-free subcommand chowns the workspace, drops the guest
//!      capability bounding set and supplementary groups, transitions to the workload
//!      identity, re-runs runtime qualification (Landlock/socket probes), and starts the
//!      boundary server on /.openshell/channel/sandbox/sandbox.sock.
//!   3. PID 1 waits on the boundary; its exit status becomes the container's exit status.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// Workload identity. Keep in sync with driver.rs::DEFAULT_WORKLOAD_UID/GID.
const WORKLOAD_UID: u32 = 1000;
const WORKLOAD_GID: u32 = 1000;

/// Mount point inside the guest where the driver bind-mounts the per-sandbox
/// channel/sandbox staging directory (bootstrap.json + server.crt/key).
/// Keep in sync with `driver.rs::CHANNEL_STATE_DIR_MOUNT_PATH` +
/// `CHANNEL_SANDBOX_SUBDIR` (`/.openshell/channel/sandbox`).
const CHANNEL_SANDBOX_MOUNT_DIR: &str = "/.openshell/channel/sandbox";

/// Where the driver bind-mounts the Linux binaries.
/// Keep in sync with `driver.rs::SUPERVISOR_DIR_MOUNT_PATH`.
const BIN_DIR: &str = "/opt/openshell/bin";

const BOOTSTRAP_FILE: &str = "bootstrap.json";
const SERVER_CERT_FILE: &str = "server.crt";
const SERVER_KEY_FILE: &str = "server.key";

fn main() -> std::process::ExitCode {
    let channel_dir = PathBuf::from(CHANNEL_SANDBOX_MOUNT_DIR);
    let bootstrap = channel_dir.join(BOOTSTRAP_FILE);
    let server_cert = channel_dir.join(SERVER_CERT_FILE);
    let server_key = channel_dir.join(SERVER_KEY_FILE);

    for path in [&bootstrap, &server_cert, &server_key] {
        if let Err(err) = std::fs::metadata(path) {
            eprintln!(
                "trybox-entrypoint: required staged file {} is missing: {err}",
                path.display()
            );
            return std::process::ExitCode::from(2);
        }
    }

    let sandbox_bin = PathBuf::from(BIN_DIR).join("openshell-sandbox");

    let mut boundary: Child = match Command::new(&sandbox_bin)
        .arg("launch-capability-free")
        .arg(WORKLOAD_UID.to_string())
        .arg(WORKLOAD_GID.to_string())
        .arg(&bootstrap)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            eprintln!(
                "trybox-entrypoint: spawn {} failed: {err}",
                sandbox_bin.display()
            );
            return std::process::ExitCode::from(3);
        }
    };

    match boundary.wait() {
        Ok(status) => std::process::ExitCode::from(status.code().unwrap_or(1).clamp(0, 255) as u8),
        Err(err) => {
            eprintln!("trybox-entrypoint: wait on boundary failed: {err}");
            std::process::ExitCode::from(4)
        }
    }
}
