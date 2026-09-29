// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! trybox-entrypoint — PID 1 inside each Apple Container sandbox guest.
//!
//! spawns the supervisor+workload pair:
//!   * `/opt/openshell/bin/openshell-supervisor \
//!      --backend-descriptor-file=/.openshell/supervisor/backend-descriptor.json \
//!      --auth-bundle-file=/.openshell/supervisor/auth.json`
//!   * `/opt/openshell/bin/openshell-sandbox \
//!      --bootstrap /.openshell/channel/sandbox/bootstrap.json`
//!
//! and waits for either child to exit. The exit status of the first child to
//! exit becomes the container's exit status. A best-effort SIGTERM is sent to
//! the survivor so the pair always tears down together.

use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// Workload identity. Keep in sync with driver.rs::DEFAULT_WORKLOAD_UID/GID.
const WORKLOAD_UID: u32 = 1000;
const WORKLOAD_GID: u32 = 1000;

/// Mount point inside the guest where the driver bind-mounts the per-sandbox
/// supervisor staging directory (auth.json + backend-descriptor.json).
/// Keep in sync with `driver.rs::SUPERVISOR_STATE_DIR_MOUNT_PATH`
/// (`/.openshell/supervisor`).
const SUPERVISOR_MOUNT_DIR: &str = "/.openshell/supervisor";

/// Mount point inside the guest where the driver bind-mounts the per-sandbox
/// channel/sandbox staging directory (bootstrap.json + server.crt/key).
/// Keep in sync with `driver.rs::CHANNEL_STATE_DIR_MOUNT_PATH` +
/// `CHANNEL_SANDBOX_SUBDIR` (`/.openshell/channel/sandbox`).
const CHANNEL_SANDBOX_MOUNT_DIR: &str = "/.openshell/channel/sandbox";

/// Where the driver bind-mounts the Linux supervisor + sandbox binaries.
/// Keep in sync with `driver.rs::SUPERVISOR_DIR_MOUNT_PATH`
/// (`/opt/openshell/bin`).
const BIN_DIR: &str = "/opt/openshell/bin";

const AUTH_BUNDLE_FILE: &str = "auth.json";
const BACKEND_DESCRIPTOR_FILE: &str = "backend-descriptor.json";
const BOOTSTRAP_FILE: &str = "bootstrap.json";

fn main() -> std::process::ExitCode {
    let auth_bundle = PathBuf::from(SUPERVISOR_MOUNT_DIR).join(AUTH_BUNDLE_FILE);
    let backend_descriptor = PathBuf::from(SUPERVISOR_MOUNT_DIR).join(BACKEND_DESCRIPTOR_FILE);
    let bootstrap = PathBuf::from(CHANNEL_SANDBOX_MOUNT_DIR).join(BOOTSTRAP_FILE);

    let supervisor_bin = PathBuf::from(BIN_DIR).join("openshell-supervisor");
    let sandbox_bin = PathBuf::from(BIN_DIR).join("openshell-sandbox");

    for path in [&auth_bundle, &backend_descriptor, &bootstrap] {
        if let Err(err) = std::fs::metadata(path) {
            eprintln!(
                "trybox-entrypoint: required staged file {} is missing: {err}",
                path.display()
            );
            return std::process::ExitCode::from(2);
        }
    }

    let mut supervisor = match Command::new(&supervisor_bin)
        .arg(format!(
            "--backend-descriptor-file={}",
            backend_descriptor.display()
        ))
        .arg(format!("--auth-bundle-file={}", auth_bundle.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            eprintln!(
                "trybox-entrypoint: spawn {} failed: {err}",
                supervisor_bin.display()
            );
            return std::process::ExitCode::from(3);
        }
    };

    let mut sandbox = {
        let mut cmd = Command::new(&sandbox_bin);
        cmd.arg("--bootstrap")
            .arg(&bootstrap)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        unsafe {
            cmd.pre_exec(|| {
                // Drop privileges to the workload identity before exec'ing the boundary.
                // libc::setgid/uid require no capabilities in the called-within-root context.
                if libc::setgid(WORKLOAD_GID) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(WORKLOAD_UID) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        match cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                eprintln!(
                    "trybox-entrypoint: spawn {} failed: {err}",
                    sandbox_bin.display()
                );
                let _ = supervisor.kill();
                let _ = supervisor.wait();
                return std::process::ExitCode::from(4);
            }
        }
    };

    // Wait for either to exit; kill the survivor.
    let code = wait_for_first(&mut supervisor, &mut sandbox);
    std::process::ExitCode::from(code)
}

/// Wait for either child to exit; signal the survivor, wait for it, return
/// the first child's exit code (or 1 if status had no code).
fn wait_for_first(supervisor: &mut Child, sandbox: &mut Child) -> u8 {
    loop {
        if let Ok(Some(status)) = supervisor.try_wait() {
            let _ = sandbox.kill();
            let _ = sandbox.wait();
            return status.code().unwrap_or(1).clamp(0, 255) as u8;
        }
        if let Ok(Some(status)) = sandbox.try_wait() {
            let _ = supervisor.kill();
            let _ = supervisor.wait();
            return status.code().unwrap_or(1).clamp(0, 255) as u8;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
