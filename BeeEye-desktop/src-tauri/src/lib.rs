// The crate name mirrors this repo's "BeeEye-*" convention (every other
// module/directory is named the same way) rather than Rust's usual snake_case.
#![allow(non_snake_case)]

//! BeeEye-desktop: a thin Tauri shell around the existing BeeEye-gui web UI
//! (see program.md / PROGRESS.md — "只是想要独立桌面窗口", not a rewrite).
//!
//! This crate duplicates none of BeeEye-gui's React frontend or Go backend.
//! What it does, in order:
//!   1. Look for a BeeEye-gui backend already answering on the target port.
//!   2. If none is running, spawn one (the CUDA build if present, matching
//!      scripts/dev.sh's own preference) as a child process.
//!   3. Poll the port until it accepts a connection, then navigate the
//!      window from the placeholder page to the real backend URL — the
//!      window is otherwise just a browser pointed at localhost.
//!   4. On window close, kill only the child process this instance started;
//!      a backend the user already had running (e.g. via dev.sh) is left
//!      alone, since this instance doesn't own its lifecycle.

use std::io::ErrorKind;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tauri::{Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};

const GUI_PORT: u16 = 8081;
const BACKEND_STARTUP_TIMEOUT: Duration = Duration::from_secs(15);

/// Holds the child process this instance spawned, if any, so it can be
/// killed on window close. `None` means either nothing was spawned (a
/// backend was already running) or spawning hasn't happened yet.
struct ManagedChild(Mutex<Option<Child>>);

pub fn run() {
    tauri::Builder::default()
        .manage(ManagedChild(Mutex::new(None)))
        .setup(|app| {
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                if let Err(e) = ensure_backend_and_navigate(&handle) {
                    eprintln!("BeeEye-desktop: {e}");
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(event, WindowEvent::CloseRequested { .. } | WindowEvent::Destroyed) {
                let taken = {
                    let state = window.state::<ManagedChild>();
                    let mut guard = match state.0.lock() {
                        Ok(g) => g,
                        Err(_) => return,
                    };
                    guard.take()
                };
                if let Some(mut child) = taken {
                    // Only reached for a child *we* spawned — see the
                    // module doc. A pre-existing backend is never here.
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running BeeEye-desktop");
}

fn ensure_backend_and_navigate(app: &tauri::AppHandle) -> Result<(), String> {
    if !port_open(GUI_PORT) {
        let bin = find_gui_binary().ok_or_else(|| {
            "cannot locate a BeeEye-gui(-cuda) binary — set BEEEYE_GUI_BIN or run one manually \
             (e.g. via scripts/dev.sh) before starting BeeEye-desktop"
                .to_string()
        })?;
        let child = spawn_backend(&bin)?;
        let state = app.state::<ManagedChild>();
        *state.0.lock().map_err(|e| e.to_string())? = Some(child);
    }

    wait_for_port(GUI_PORT, BACKEND_STARTUP_TIMEOUT)
        .map_err(|e| format!("BeeEye-gui backend on :{GUI_PORT} never became reachable: {e}"))?;

    let url = format!("http://127.0.0.1:{GUI_PORT}");
    let parsed: tauri::Url = url.parse().map_err(|e| format!("invalid backend URL: {e}"))?;
    match app.get_webview_window("main") {
        Some(w) => w.navigate(parsed).map_err(|e| e.to_string()),
        None => {
            // The window from tauri.conf.json's `app.windows` should already
            // exist by the time setup() runs; this is a fallback, not the
            // expected path.
            WebviewWindowBuilder::new(app, "main", WebviewUrl::External(parsed))
                .build()
                .map_err(|e| e.to_string())?;
            Ok(())
        }
    }
}

fn port_open(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).is_ok()
}

fn wait_for_port(port: u16, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if port_open(port) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out after {timeout:?}"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Finds a BeeEye-gui(-cuda) binary, preferring (in order):
///   1. $BEEEYE_GUI_BIN, if set — an explicit override.
///   2. Walking up from this executable's own location looking for
///      BeeEye-agent/bin/{BeeEye-gui-cuda,BeeEye-gui}, which is where they
///      land relative to the repo root regardless of whether this binary is
///      running from `cargo tauri dev`'s target/ or a packaged install that
///      preserves the repo layout.
fn find_gui_binary() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BEEEYE_GUI_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }

    let exe = std::env::current_exe().ok()?;
    let mut dir: &Path = exe.parent()?;
    loop {
        for name in ["BeeEye-gui-cuda", "BeeEye-gui"] {
            let candidate = dir.join("BeeEye-agent").join("bin").join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        dir = dir.parent()?;
    }
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

fn spawn_backend(bin: &Path) -> Result<Child, String> {
    let iface = pick_interface();
    eprintln!("BeeEye-desktop: starting {} -listen :{GUI_PORT} -iface {iface}", bin.display());
    Command::new(bin)
        .arg("-listen")
        .arg(format!(":{GUI_PORT}"))
        .arg("-iface")
        .arg(&iface)
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
