// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! trybox-entrypoint — PID 1 inside each Apple Container guest.
//!
//! Mirrors the openshell-driver-vm guest agent: the supervisor lives on the
//! macOS host, and the guest-side boundary process (`openshell-sandbox
//! launch-capability-free`) runs inside the Apple VM. The VM hypervisor is
//! the security boundary. The boundary drops to uid/gid 1000 via upstream's
//! `launch-capability-free` subcommand, matching the podman workload model.
//!
//! Staging layout (host-owned, virtiofs-bridged into the guest):
//!   channel mount    → /.openshell/channel/sandbox/{bootstrap.json,server.crt,server.key}
//!   supervisor mount → /.openshell/supervisor/{auth.json,backend-descriptor.json}
use std::path::PathBuf;
use std::process::{Command, Stdio};

const GUEST_BIN_DIR: &str = "/opt/openshell/bin";
const SANDBOX_BIN: &str = "openshell-sandbox";
const CHANNEL_MOUNT_DIR: &str = "/.openshell/channel";
const CHANNEL_SANDBOX_SUBDIR: &str = "sandbox";
const BOOTSTRAP_FILE: &str = "bootstrap.json";
const WORKLOAD_UID: u32 = 1000;
const WORKLOAD_GID: u32 = 1000;
/// Apple container runtime does not expose a `--sysctl` knob and mounts
/// /proc/sys read-only, so the entrypoint re-binds it writable via mount(2)
/// before lowering the unprivileged-port knob (requires CAP_SYS_ADMIN, which
/// the driver enables for the entrypoint container).
const UNPRIVILEGED_PORT_START_SYSCTL: &str = "/proc/sys/net/ipv4/ip_unprivileged_port_start";
const UNPRIVILEGED_PORT_START_VALUE: &[u8] = b"0\n";

fn main() -> std::process::ExitCode {
    match run() {
        Ok(code) => std::process::ExitCode::from(code),
        Err(err) => {
            eprintln!("trybox-entrypoint: {err}");
            std::process::ExitCode::from(1)
        }
    }
}

/// Re-bind /proc/sys/net writable (best-effort) and write the sysctl the
/// upstream podman driver normally passes via `--sysctl
/// net.ipv4.ip_unprivileged_port_start=0`. Needed so the capability-free
/// boundary process can bind its DNS relay probe at 127.0.0.53:53.
fn write_ctl_tweak() {
    let sys_net = PathBuf::from("/proc/sys/net");

    // Bind /proc/sys/net over itself to flip to writeable view, then remount rw.
    match Command::new("mount")
        .args([
            "--bind".to_string(),
            sys_net.display().to_string(),
            sys_net.display().to_string(),
        ])
        .status()
    {
        Ok(status) if status.success() => {}
        other => {
            eprintln!(
                "trybox-entrypoint: bind /proc/sys/net failed: {:?}; continuing",
                other
            );
        }
    }

    match Command::new("mount")
        .args(["-o".to_string(), "remount,rw".to_string(), sys_net.display().to_string()])
        .status()
    {
        Ok(status) if status.success() => {}
        other => {
            eprintln!(
                "trybox-entrypoint: remount /proc/sys/net rw failed: {:?}; continuing",
                other
            );
        }
    }

    if let Err(err) = std::fs::write(
        UNPRIVILEGED_PORT_START_SYSCTL,
        UNPRIVILEGED_PORT_START_VALUE,
    ) {
        eprintln!(
            "trybox-entrypoint: write {} failed: {err}; continuing",
            UNPRIVILEGED_PORT_START_SYSCTL
        );
    }
}

/// chown the staged channel/sandbox material to the workload identity so the
/// boundary (dropping to uid=1000) can unlink any stale socket inode when it
/// starts. virtiofs shows host-side owner ids to the guest, so without this
/// pre-step the boundary sees the host's uid (e.g. 501) and refuses to remove
/// a "owner-mismatched" socket.
fn synchronize_ownership(dir: &PathBuf, uid: u32, gid: u32) {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name() else { continue };
        let _ = Command::new("chown")
            .arg("-h")
            .arg(format!("{uid}:{gid}"))
            .arg(&path)
            .status();
        let _ = name;
    }
}

fn run() -> std::io::Result<u8> {
    // Apple container runtime lacks `--sysctl` and ships /proc/sys read-only.
    write_ctl_tweak();

    let bootstrap = PathBuf::from(CHANNEL_MOUNT_DIR)
        .join(CHANNEL_SANDBOX_SUBDIR)
        .join(BOOTSTRAP_FILE);

    if !bootstrap.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("bootstrap not present at {}", bootstrap.display()),
        ));
    }

    // Boundary's listener only unlinks a stale socket when its inode owner
    // matches the boundary's effective UID. The staged files arrive HOST-owned
    // (typically uid 501) through virtiofs, while the boundary drops to uid
    // 1000. Pre-chown the staged sandboxes material to the workload identity
    // and pre-unlink any stale leftover socket so the bind can proceed.
    let sandbox_dir = PathBuf::from(CHANNEL_MOUNT_DIR).join(CHANNEL_SANDBOX_SUBDIR);
    for stale in [
        sandbox_dir.join("sandbox.sock"),
        sandbox_dir.join("test.sock"),
    ] {
        let _ = std::fs::remove_file(&stale);
    }
    synchronize_ownership(&sandbox_dir, WORKLOAD_UID, WORKLOAD_GID);

    let sandbox_bin = PathBuf::from(GUEST_BIN_DIR).join(SANDBOX_BIN);
    println!(
        "trybox-entrypoint: boundary {} launch-capability-free {} {} {}",
        sandbox_bin.display(),
        WORKLOAD_UID,
        WORKLOAD_GID,
        bootstrap.display()
    );

    let mut sandbox = {
        let mut cmd = Command::new(&sandbox_bin);
        cmd.arg("launch-capability-free")
            .arg(WORKLOAD_UID.to_string())
            .arg(WORKLOAD_GID.to_string())
            .arg(&bootstrap)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        match cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                eprintln!(
                    "trybox-entrypoint: spawn {} failed: {err}",
                    sandbox_bin.display()
                );
                return Err(err);
            }
        }
    };

    let status = sandbox.wait()?;
    let code: u8 = status.code().map_or(75, |code| {
        code.clamp(0, 255).to_string().parse::<u8>().unwrap_or(75)
    });
    println!("trybox-entrypoint: boundary exit code {code}");
    Ok(code)
}
