//! §7.1.0 Overview — SARX Watcher (separate process)
//! Watches folders listed in ~/.sarx_watchfolders for new/changed files,
//! encrypts them with `sarx encrypt`, parses the generated password, and
//! saves it to Sigilbook. Non-recursive watchers, 1s stability wait.
//!
//! Program v7.0.0 — Sections §7.X.0

use anyhow::{Context, Result};
use notify::{
    event::{CreateKind, DataChange, ModifyKind, RenameMode},
    Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use std::{
    ffi::OsStr,
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

fn main() -> Result<()> {
    let folders = read_watchlist()?;
    if folders.is_empty() {
        eprintln!("No folders to watch. Add some to ~/.sarx_watchfolders and re-run. Exiting.");
        return Ok(());
    }

    eprintln!("[SARX Watcher] Watching {} folder(s):", folders.len());
    for f in &folders {
        eprintln!("  - {}", f.display());
    }

    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();

    // notify 6 uses callback-based watchers; forward into our mpsc channel.
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            // best-effort: ignore send errors on shutdown
            let _ = tx.send(res);
        },
        Config::default(),
    )?;

    for dir in &folders {
        watcher
            .watch(dir, RecursiveMode::NonRecursive)
            .with_context(|| format!("watch {:?}", dir))?;
    }

    // Simple debounce to avoid double-processing the same path rapidly.
    let mut last_processed: std::collections::HashMap<PathBuf, Instant> =
        std::collections::HashMap::new();
    let debounce = Duration::from_millis(400);

    for res in rx {
        let event = match res {
            Ok(ev) => ev,
            Err(e) => {
                eprintln!("[SARX Watcher] notify error: {e}");
                continue;
            }
        };

        // Filter event kinds we care about.
        if !is_relevant_event(&event.kind) {
            continue;
        }

        for p in event.paths {
            // Only files, skip .vault
            if p
                .extension()
                .and_then(OsStr::to_str)
                .map(|ext| ext.eq_ignore_ascii_case("vault"))
                .unwrap_or(false)
            {
                continue;
            }

            // Debounce
            let now = Instant::now();
            let do_skip = last_processed
                .get(&p)
                .map(|last| now.duration_since(*last) < debounce)
                .unwrap_or(false);
            if do_skip {
                continue;
            }
            last_processed.insert(p.clone(), now);

            // Spawn per-file worker so the loop stays responsive.
            thread::spawn(move || {
                if let Err(e) = handle_file_event(&p) {
                    eprintln!("[SARX Watcher] Error for {}: {e:#}", p.display());
                }
            });
        }
    }

    Ok(())
}

// ============================================================================
// §7.2.0 Event Handling
// ============================================================================
fn handle_file_event(path: &Path) -> Result<()> {
    // Must be a regular file
    if !is_regular_file(path) {
        return Ok(());
    }

    // Wait for stability (<= 1s, 50ms steps)
    if !wait_for_stable(path, Duration::from_secs(1), Duration::from_millis(50))? {
        eprintln!("[SARX Watcher] File did not stabilize: {}", path.display());
        return Ok(());
    }

    eprintln!("[SARX Watcher] Encrypting: {}", path.display());

    // sarx encrypt <file>
    let (password_opt, combined_out) = run_sarx_encrypt(path)?;
    let vault = vault_path_for(path);

    if let Some(pw) = password_opt {
        if vault.is_file() {
            // Save to sigilbook
            if let Err(e) = sigilbook_save(&vault, &pw) {
                eprintln!(
                    "[SARX Watcher] Failed to save password to sigilbook: {} ({:#})",
                    vault.display(),
                    e
                );
            } else {
                eprintln!("[SARX Watcher] Password saved: {}", vault.display());
            }
        } else {
            eprintln!(
                "[SARX Watcher] Encrypt reported password, but vault not found: {}",
                vault.display()
            );
            eprintln!("{}", combined_out);
        }
    } else {
        eprintln!(
            "[SARX Watcher] Encrypt failed or no password captured: {}",
            path.display()
        );
        eprintln!("{}", combined_out);
    }

    Ok(())
}

// ============================================================================
// §7.3.0 Helpers
// ============================================================================
fn read_watchlist() -> Result<Vec<PathBuf>> {
    let list_path = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("No $HOME"))?
        .join(".sarx_watchfolders");

    let f = match fs::File::open(&list_path) {
        Ok(f) => f,
        Err(_) => return Ok(Vec::new()),
    };

    let mut out = Vec::new();
    for line in BufReader::new(f).lines().flatten() {
        let p = PathBuf::from(line.trim());
        if !p.as_os_str().is_empty() {
            if let Ok(canon) = fs::canonicalize(&p) {
                if canon.is_dir() && !out.contains(&canon) {
                    out.push(canon);
                }
            }
        }
    }
    Ok(out)
}

fn is_regular_file(p: &Path) -> bool {
    match fs::metadata(p) {
        Ok(m) => m.is_file(),
        Err(_) => false,
    }
}

/// Wait until the file exists, is non-empty, and its size is stable across two polls.
fn wait_for_stable(p: &Path, max: Duration, step: Duration) -> Result<bool> {
    let deadline = Instant::now() + max;
    let mut prev_len: Option<u64> = None;
    loop {
        if Instant::now() >= deadline {
            return Ok(false);
        }
        let ok = if let Ok(meta) = fs::metadata(p) {
            if meta.is_file() {
                let len = meta.len();
                if len > 0 {
                    if let Some(pl) = prev_len {
                        pl == len
                    } else {
                        prev_len = Some(len);
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };
        if ok {
            return Ok(true);
        }
        thread::sleep(step);
    }
}

fn run_sarx_encrypt(file: &Path) -> Result<(Option<String>, String)> {
    let output = Command::new("sarx")
        .arg("encrypt")
        .arg(file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("launch sarx encrypt for {}", file.display()))?;

    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
    }

    // Parse "Password: ..." line first
    let mut password: Option<String> = None;
    for line in combined.lines() {
        if let Some(rest) = line.strip_prefix("Password: ") {
            password = Some(rest.trim().to_string());
            break;
        }
    }
    // Fallback: first non-blank, non-✅ line
    if password.is_none() {
        for line in combined.lines() {
            let s = line.trim();
            if !s.is_empty() && !s.starts_with('✅') {
                password = Some(s.to_string());
                break;
            }
        }
    }

    Ok((password, combined))
}

fn sigilbook_save(vault: &Path, password: &str) -> Result<()> {
    let mut child = Command::new("sigilbook")
        .arg("save")
        .arg(vault)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn sigilbook save")?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(password.as_bytes())
            .context("write pw to sigilbook stdin")?;
    }
    let status = child.wait().context("wait sigilbook save")?;
    if !status.success() {
        anyhow::bail!("sigilbook save exited with {}", status);
    }
    Ok(())
}

fn vault_path_for(plain: &Path) -> PathBuf {
    let mut s = plain.as_os_str().to_os_string();
    s.push(".vault");
    PathBuf::from(s)
}

/// Decide which notify events matter for our pipeline.
fn is_relevant_event(kind: &EventKind) -> bool {
    match kind {
        EventKind::Create(CreateKind::File) => true,
        EventKind::Modify(ModifyKind::Data(DataChange::Any)) => true,
        EventKind::Modify(ModifyKind::Data(DataChange::Content)) => true,
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => true,
        EventKind::Modify(ModifyKind::Any) => true,
        // Some backends emit generic Modify for close_write-like behavior
        EventKind::Modify(_) => true,
        // We ignore Remove/Access/Other
        _ => false,
    }
}