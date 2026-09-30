// SPDX-License-Identifier: Apache-2.0
//! Guest PID 1: enforce the network fence, copy bootstrap off virtiofs, then
//! replace ourselves with the upstream capability-free boundary launcher.
use std::io::{Error, Result};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

fn checked(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        return Err(Error::other(format!("{program} {args:?} failed: {status}")));
    }
    Ok(())
}

fn network_fence() -> Result<()> {
    // These are fresh per-VM tables. Fail closed before the workload starts.
    // No NEW connection may leave a NIC, including DNS or access to the host.
    // Only the pinned TLS control connection can enter from outside the guest.
    for tool in ["iptables", "ip6tables"] {
        for chain in ["INPUT", "FORWARD", "OUTPUT"] {
            checked(tool, &["-w", "-P", chain, "DROP"])?;
        }
        checked(tool, &["-w", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])?;
        checked(tool, &["-w", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])?;
        for chain in ["INPUT", "OUTPUT"] {
            checked(
                tool,
                &[
                    "-w",
                    "-A",
                    chain,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
            )?;
        }
    }
    checked(
        "iptables",
        &[
            "-w", "-A", "INPUT", "-p", "tcp", "--dport", "17672", "-j", "ACCEPT",
        ],
    )?;
    Ok(())
}

fn run() -> Result<()> {
    network_fence()?;
    checked("mount", &["--bind", "/proc/sys/net", "/proc/sys/net"])?;
    checked("mount", &["-o", "remount,rw", "/proc/sys/net"])?;
    std::fs::write("/proc/sys/net/ipv4/ip_unprivileged_port_start", b"0\n")?;

    let runtime = Path::new("/run/trybox");
    std::fs::create_dir_all(runtime)?;
    std::fs::set_permissions(runtime, std::fs::Permissions::from_mode(0o700))?;
    std::fs::write(runtime.join("resolv.conf"), b"nameserver 127.0.0.53\n")?;
    checked(
        "mount",
        &["--bind", "/run/trybox/resolv.conf", "/etc/resolv.conf"],
    )?;
    for name in ["bootstrap.json", "server.crt", "server.key"] {
        let destination = runtime.join(name);
        std::fs::copy(
            Path::new("/.openshell/channel/sandbox").join(name),
            &destination,
        )?;
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o600))?;
    }
    checked("chown", &["-R", "1000:1000", "/run/trybox"])?;
    let ca_dir = Path::new("/run/openshell-supervisor-ca");
    std::fs::create_dir_all(ca_dir)?;
    std::fs::set_permissions(ca_dir, std::fs::Permissions::from_mode(0o755))?;
    checked("chown", &["1000:1000", "/run/openshell-supervisor-ca"])?;
    // No privileged parent remains. The upstream launcher drops all capabilities
    // and sets no_new_privs before processing any workload request.
    Err(Command::new("/opt/openshell/bin/openshell-sandbox")
        .args([
            "launch-capability-free",
            "1000",
            "1000",
            "/run/trybox/bootstrap.json",
            "/sandbox",
        ])
        .exec())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("trybox-entrypoint: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
