// The crate name mirrors this repo's "BeeEye-*" convention (every other
// module/directory is named the same way) rather than Rust's usual snake_case.
#![allow(non_snake_case)]

//! BeeEye-desktop: a thin Tauri shell that puts both existing web UIs —
//! the overview UI (BeeEye-web, served by BeeEye-agent on :8080) and the
//! analyzer UI (BeeEye-gui, on :8081) — behind one native window with an
//! in-page tab switcher (see program.md / PROGRESS.md — "只是想要独立桌面
//! 窗口", not a rewrite; both UIs sharing a window instead of the app
//! opening two separate windows was an explicit later request).
//!
//! This crate duplicates none of either frontend's React or Go code. What
//! it does, in order:
//!   1. Look for a BeeEye-gui backend already answering on :8081, and a
//!      BeeEye-agent backend already answering on :8080.
//!   2. Spawn whichever of the two is not already running (the CUDA build of
//!      each if present, matching scripts/dev.sh's own preference) as a
//!      child process.
//!   3. Stay on its own shell page (dist-placeholder/index.html) rather
//!      than navigating away from it — that page polls both :8080 and
//!      :8081 from JS and loads each into its own <iframe> once reachable,
//!      switched by a tab bar.
//!   4. On window close, stop both backends — the analyzer on :8081 and the
//!      overview daemon (BeeEye-agent) on :8080 — regardless of which one
//!      this instance itself started. Closing the only window this desktop
//!      app has is the user's signal that BeeEye should stop entirely; a
//!      quit that silently leaves capture/decrypt processes running in the
//!      background is the surprising behaviour, not this one. (An earlier
//!      version only killed a child it had spawned itself, to avoid
//!      touching a backend someone started by hand via start.sh/dev.sh —
//!      that trade was deliberately reversed on request: for this desktop
//!      shell, "the window is BeeEye" beats "don't touch what I didn't
//!      start." Running the stack independently of the desktop app, e.g.
//!      for a headless gateway, is what start.sh/systemd are for.)
//!
//!      Step 1/2 used to only ever look at :8081 — BeeEye-agent was left for
//!      "start.sh/systemd" to worry about, on the reasoning that it is the
//!      main long-running daemon and its lifecycle should not depend on a
//!      GUI window's. That reasoning never actually held here: the
//!      window-close handler already stops BOTH backends unconditionally
//!      (see point 4's own note about that trade already being made), so a
//!      user who launched this app on its own — the installed .deb's
//!      desktop-launcher entry, not `start.sh`/`dev.sh` first — got a
//!      window whose Overview tab could never leave "not ready": nothing had
//!      ever asked BeeEye-agent to start. Spawning both, symmetrically with
//!      how both already get stopped, is that inconsistency resolved in the
//!      one direction consistent with the rest of this file.

use std::io::ErrorKind;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use tauri::{Manager, WindowEvent};

const GUI_PORT: u16 = 8081;
const OVERVIEW_PORT: u16 = 8080;

/// Holds whichever child processes this instance spawned (0, 1 or 2 of
/// them — gui, agent, both, or neither if both were already running), so
/// they can be killed on window close. Empty means either nothing was
/// spawned or spawning hasn't happened yet.
struct ManagedChildren(Mutex<Vec<Child>>);

pub fn run() {
    tauri::Builder::default()
        .manage(ManagedChildren(Mutex::new(Vec::new())))
        .setup(|app| {
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                if let Err(e) = ensure_gui(&handle) {
                    eprintln!("BeeEye-desktop: {e}");
                }
                if let Err(e) = ensure_agent(&handle) {
                    eprintln!("BeeEye-desktop: {e}");
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(event, WindowEvent::CloseRequested { .. } | WindowEvent::Destroyed) {
                let taken = {
                    let state = window.state::<ManagedChildren>();
                    let mut guard = match state.0.lock() {
                        Ok(g) => g,
                        Err(_) => return,
                    };
                    std::mem::take(&mut *guard)
                };
                for mut child in taken {
                    // The fast, direct path when this instance is the one
                    // that spawned a backend.
                    let _ = child.kill();
                    let _ = child.wait();
                }
                // Whatever is still listening on either port — started by
                // this instance or found already running — closing the
                // window means stopping BeeEye, full stop. See the module
                // doc for why this reaches beyond what this instance itself
                // started.
                kill_backend(GUI_PORT, "gui");
                kill_backend(OVERVIEW_PORT, "agent");
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running BeeEye-desktop");
}

fn ensure_gui(app: &tauri::AppHandle) -> Result<(), String> {
    if port_open(GUI_PORT) {
        return Ok(());
    }
    let bin = find_gui_binary().ok_or_else(|| {
        "cannot locate a BeeEye-gui(-cuda) binary — set BEEEYE_GUI_BIN or run one manually \
         (e.g. via scripts/dev.sh) before starting BeeEye-desktop"
            .to_string()
    })?;
    let child = spawn_gui(&bin)?;
    push_child(app, child)
}

/// Overview's counterpart to ensure_gui — see this file's module doc for why
/// both are spawned symmetrically now instead of only the analyzer.
fn ensure_agent(app: &tauri::AppHandle) -> Result<(), String> {
    if port_open(OVERVIEW_PORT) {
        return Ok(());
    }
    let root = repo_root().ok_or_else(|| {
        "cannot locate the BeeEye repo root from this executable's path".to_string()
    })?;
    let bin = find_agent_binary(&root).ok_or_else(|| {
        "cannot locate a BeeEye-agent(-cuda) binary — set BEEEYE_AGENT_BIN or run one manually \
         (e.g. via scripts/dev.sh) before starting BeeEye-desktop"
            .to_string()
    })?;
    let child = spawn_agent(&bin, &root)?;
    push_child(app, child)
}

fn push_child(app: &tauri::AppHandle, child: Child) -> Result<(), String> {
    let state = app.state::<ManagedChildren>();
    state.0.lock().map_err(|e| e.to_string())?.push(child);
    Ok(())
}

fn port_open(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).is_ok()
}

/// Finds the pid of whatever is listening on port by shelling out to `ss`
/// (present on essentially every Linux desktop; no crate needed for one
/// lookup used only at window-close time). `ss -tlnp`'s process column looks
/// like `users:(("BeeEye-agent",pid=12345,fd=25))` — pull the digits after
/// "pid=".
///
/// This comes back empty for BeeEye-agent/BeeEye-gui(-cuda) specifically,
/// which is why kill_backend below does not rely on it alone: granting a
/// binary capabilities via setcap (cap_net_raw etc. — see INSTALL.md §4)
/// makes the kernel mark that process non-dumpable, and `ss -p`'s pid
/// column comes from reading /proc/<pid>/fd, which needs ptrace access a
/// non-dumpable process denies to everyone but a CAP_SYS_PTRACE holder —
/// even another process running as the very same user. This is the exact
/// mechanism documented at length in BeeEye-agent/internal/tlspeek and
/// TLS-DECRYPT.md for a completely different symptom (uprobes needing
/// CAP_SYS_PTRACE to read their own /proc/self/mem); same kernel rule, two
/// unrelated features tripped by it.
fn pid_on_port(port: u16) -> Option<u32> {
    let out = Command::new("ss").args(["-tlnp"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let needle = format!(":{port} ");
    for line in text.lines() {
        if !line.contains(&needle) {
            continue;
        }
        let after = line.split("pid=").nth(1)?;
        let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(pid) = digits.parse() {
            return Some(pid);
        }
    }
    None
}

/// Reads the pid start.sh recorded at `.run/<name>.pid` when it started the
/// process — the reliable source for BeeEye-agent/BeeEye-gui(-cuda)
/// specifically, since pid_on_port's /proc/<pid>/fd introspection is exactly
/// what their own setcap capabilities block (see pid_on_port's doc). A
/// plain pid file has no such requirement: reading a text file needs no
/// ptrace access to anything.
fn pid_from_runfile(name: &str) -> Option<u32> {
    let text = std::fs::read_to_string(repo_root()?.join(".run").join(format!("{name}.pid"))).ok()?;
    text.trim().parse().ok()
}

/// Whether pid is still a live process. Checking /proc/<pid>'s existence
/// needs no special access to any *other* process's internals — unlike
/// pid_on_port, this is unaffected by the non-dumpable/setcap situation
/// above, which is why it is what decides whether SIGKILL is needed rather
/// than re-running pid_on_port and risking the same blind spot.
fn pid_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).is_dir()
}

/// Stops whatever is listening on port, whether or not this instance is what
/// started it — see the module doc. Best-effort and quiet: a window close
/// must never hang or panic because a process already exited, the lookup
/// tool is missing, or a permission check failed.
///
/// runfile_name is the start.sh-recorded pid file to prefer (see
/// pid_from_runfile); pid_on_port is the fallback for a backend started
/// some other way, which start.sh itself was never involved in.
///
/// SIGTERM first, so BeeEye-agent gets to close its SQLite handle and flush
/// the pcap it may be writing rather than losing the tail of a capture;
/// SIGKILL only if it is still there shortly after.
fn kill_backend(port: u16, runfile_name: &str) {
    let Some(pid) = pid_from_runfile(runfile_name).or_else(|| pid_on_port(port)) else { return };
    let _ = Command::new("kill").arg(pid.to_string()).status();
    std::thread::sleep(Duration::from_millis(800));
    if pid_alive(pid) {
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    }
}

/// Walks up from this executable's own location looking for a
/// BeeEye-agent/bin directory, which is where the repo root sits regardless
/// of whether this binary is running from `cargo tauri dev`'s target/ or a
/// packaged install that preserves the repo layout. Shared by
/// find_gui_binary (the backend binaries live under it) and
/// pid_from_runfile (.run/ lives at its top).
fn repo_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let mut dir: &Path = exe.parent()?;
    loop {
        if dir.join("BeeEye-agent").join("bin").is_dir() {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
}

/// Finds a BeeEye-gui(-cuda) binary, preferring (in order):
///   1. $BEEEYE_GUI_BIN, if set — an explicit override.
///   2. BeeEye-agent/bin/{BeeEye-gui-cuda,BeeEye-gui} under repo_root().
fn find_gui_binary() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BEEEYE_GUI_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }

    let root = repo_root()?;
    for name in ["BeeEye-gui-cuda", "BeeEye-gui"] {
        let candidate = root.join("BeeEye-agent").join("bin").join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Picks the interface BeeEye-gui should capture on: the default-route NIC
/// (via `ip route get`, the same approach scripts/dev.sh's default_iface()
/// uses), falling back to "any" — never a value that could be empty or
/// malformed, since an empty -iface argument is worse than a broad one.
fn pick_interface() -> String {
    let out = Command::new("ip")
        .args(["-o", "route", "get", "1.1.1.1"])
        .output();
    if let Ok(out) = out {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut words = text.split_whitespace();
            while let Some(w) = words.next() {
                if w == "dev" {
                    if let Some(dev) = words.next() {
                        return dev.to_string();
                    }
                }
            }
        }
    }
    "any".to_string()
}

fn spawn_gui(bin: &Path) -> Result<Child, String> {
    let iface = pick_interface();
    let mut cmd = Command::new(bin);
    cmd.arg("-listen").arg(format!(":{GUI_PORT}")).arg("-iface").arg(&iface);

    // BeeEye-gui(-cuda) defaults `-web` to the cwd-relative "./BeeEye-gui/dist".
    // That only resolves when launched from a shell already sitting at the
    // repo root (dev.sh, start.sh). Launched from a desktop entry, the cwd is
    // whatever the session sets (often $HOME) and the relative path silently
    // misses an already-built UI. `bin` was found by find_gui_binary() at
    // "<repo_root>/BeeEye-agent/bin/<name>", so the dist dir is always two
    // parents up plus BeeEye-gui/dist — pass it as an absolute path.
    if let Some(dist) = bin.parent().and_then(Path::parent).and_then(Path::parent).map(|repo_root| repo_root.join("BeeEye-gui").join("dist")) {
        if dist.is_dir() {
            cmd.arg("-web").arg(&dist);
        }
    }

    eprintln!("BeeEye-desktop: starting {} -listen :{GUI_PORT} -iface {iface}", bin.display());
    cmd
        // Inherit nothing interactive; a child window should not depend on
        // this process's stdio surviving.
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| match e.kind() {
            ErrorKind::PermissionDenied => format!(
                "{} exists but is not executable (needs raw-capture capabilities — see INSTALL.md §4)",
                bin.display()
            ),
            _ => format!("failed to start {}: {e}", bin.display()),
        })
}

/// Overview's counterpart to find_gui_binary — same override-then-repo-root
/// search, just for BeeEye-agent(-cuda) instead. Takes root rather than
/// calling repo_root() itself since ensure_agent already needs it separately
/// (spawn_agent's cwd, and the -config path below).
fn find_agent_binary(root: &Path) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BEEEYE_AGENT_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    for name in ["BeeEye-agent-cuda", "BeeEye-agent"] {
        let candidate = root.join("BeeEye-agent").join("bin").join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// BeeEye-agent's counterpart to spawn_gui. Unlike BeeEye-gui, the agent
/// takes no `-listen`/`-web` flags of its own — everything (listen_addr,
/// web_dir, port_service_map_file, the geoip/threatintel cache dirs, ...)
/// comes from config.yaml, and every one of those paths inside it is written
/// relative to the process's own working directory, not the config file's
/// location. `start.sh`/`scripts/dev.sh` always launch it from the repo
/// root, so that is the assumption those relative paths are written under;
/// setting the child's cwd to root (rather than trying to override each
/// path individually — most of which have no flag to override at all) is
/// what keeps that assumption true when a desktop launcher's own cwd is
/// something else entirely (often $HOME).
fn spawn_agent(bin: &Path, root: &Path) -> Result<Child, String> {
    let cfg = root.join("config").join("config.yaml");
    let mut cmd = Command::new(bin);
    cmd.arg("-config").arg(&cfg).current_dir(root);

    eprintln!("BeeEye-desktop: starting {} -config {} (cwd {})", bin.display(), cfg.display(), root.display());
    cmd.stdin(Stdio::null())
        .spawn()
        .map_err(|e| match e.kind() {
            ErrorKind::PermissionDenied => format!(
                "{} exists but is not executable (needs raw-capture capabilities — see INSTALL.md §4)",
                bin.display()
            ),
            _ => format!("failed to start {}: {e}", bin.display()),
        })
}
