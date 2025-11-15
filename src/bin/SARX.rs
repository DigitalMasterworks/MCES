// src/bin/sarx.rs
// Unified word-first CLI dispatcher for SARX.
// Commands:
//   sarx encrypt pw #### <file>
//   sarx decrypt pw #### <file><vault>
//   sarx verify  <vault>
//   sarx benchmark speed [--mb <int>]
//   sarx benchmark aead  [--keys N] [--ivs N] [--bytes BYTES] [--seed 0xHEX] [--log PATH]
//   sarx benchmark keystream [--threads N] [--chunk-mb N]
//   sarx record ...      (stubbed for now)
//   sarx view <vault>    (stubbed for now)
//   sarx stitch <vaults...> (stubbed for now)

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{env, fs::File, io::{Read, Seek, SeekFrom}};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use zeroize::Zeroize;
use std::io::{self, BufRead, Write};
use sarx::headers::{SARX_HEADER_BYTES, SARX_TAG_BYTES, VaultHeader};
use subtle::ConstantTimeEq;

/// Top-level CLI
#[derive(Parser)]
#[command(name="sarx", version, about="SARX word-first CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// wrap file into .vault
    Encrypt {
        file: String,
        /// optional custom password (otherwise a strong random Unicode pw is generated)
        #[arg(long)]
        password: Option<String>,
    },
    /// unwrap .vault back to original (deletes .vault on success)
    Decrypt {
        vault: String,
    },
    /// check MAC/integrity only (no decrypt). Prompts for password (TTY) or reads from stdin.
    Verify {
        vault: String,
    },
    /// benchmarks / RNG tests
    Benchmark {
        #[command(subcommand)]
        which: Bench,
    },
    /// (experimental) capture A/V into vault segments
    Record {
        #[arg(long)]
        cam: Option<String>,
        #[arg(long)]
        mic: Option<String>,
    },
    /// (experimental) decrypt + stream with ffplay
    View {
        vault: String,
    },
    /// (experimental) merge vault segments into one output
    Stitch {
        vaults: Vec<String>,
    },
    /// (new) manage watched folders for SARX watcher
    Watch {
        #[command(subcommand)]
        cmd: WatchCmd,
    },
}

#[derive(Subcommand)]
enum Bench {
    /// throughput test (sarx_bench_stream)
    Speed {
        /// optional size in MB (default 100)
        size: Option<usize>,
    },
    /// stress-test AEAD wrapper (sarx_test_harness)
    Aead,
    /// dump raw keystream (pipe to Dieharder / PractRand)
    Keystream,
}

#[derive(clap::Subcommand)]
enum WatchCmd {
    /// Add a folder to the watch list
    Add { folder: String },
    /// Remove a folder from the watch list
    Remove { folder: String },
    /// List all watched folders
    List,
}

fn main() -> Result<()> {
    // === FAST-PATH: C-style CLI, e.g. `sarx encrypt pw <pw> <file>` ===
    {
        let argv: Vec<String> = std::env::args().collect();
        // sarx encrypt pw <password> <file>
        if argv.len() == 5 && argv[1] == "encrypt" && argv[2] == "pw" {
            // Route: sarx_encrypt <file> pw <password>
            let password = argv[3].clone();
            let file     = argv[4].clone();
            let args = vec!["pw".to_string(), password, file];
            return run_sibling("sarx_encrypt", &args);
        }
        // sarx decrypt pw <password> <vault>
        if argv.len() == 5 && argv[1] == "decrypt" && argv[2] == "pw" {
            // Route: sarx_decrypt pw <password> <vault>
            let password = argv[3].clone();
            let vault    = argv[4].clone();
            let args = vec!["pw".to_string(), password, vault];
            return run_sibling("sarx_decrypt", &args);
        }
    }

    // === Standard CLI fallback (clap/subcommands) ===
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Encrypt { file, password } => {
            let mut args: Vec<String> = vec![file];
            if let Some(pw) = password {
                args.push("--password".into());
                args.push(pw);
            }
            run_sibling("sarx_encrypt", &args)
        }
        Commands::Decrypt { vault } => run_sibling("sarx_decrypt", &[vault]),
        Commands::Verify { vault } => cmd_verify(&vault),
        Commands::Benchmark { which } => match which {
            Bench::Speed { size } => {
                let mut cmd = sibling_cmd("sarx_bench_stream")?;
                if let Some(mb) = size {
                    cmd.env("SARX_MB", mb.to_string());
                }
                status_passthrough(cmd)
            }
            Bench::Aead => run_sibling("sarx_test_harness", &[] as &[&str]),
            Bench::Keystream => {
                let mut cmd = sibling_cmd("sarx_stream_dieharder")?;
                cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
                let status = cmd.status().context("launch sarx_stream_dieharder")?;
                if status.success() { Ok(()) } else { anyhow::bail!("sarx_stream_dieharder exited with {}", status) }
            }
        }
        Commands::Record { .. } => {
            eprintln!("(experimental) `sarx record` not wired yet — use `sarx_cam_gui` for now.");
            Ok(())
        }
        Commands::View { .. } => {
            eprintln!("(experimental) `sarx view` not wired yet — open via GUI (sarx_cam_gui) for now.");
            Ok(())
        }
        Commands::Stitch { .. } => {
            eprintln!("(experimental) `sarx stitch` not wired yet.");
            Ok(())
        }
        Commands::Watch { cmd } => match cmd {
            WatchCmd::Add { folder } => {
                let file = watch_file_path()?;
                let canon = canonicalize_folder(&folder)?;
                add_folder(&file, &canon)?;
                println!("Added: {}", canon.display());
                Ok(())
            }
            WatchCmd::Remove { folder } => {
                let file = watch_file_path()?;
                let canon = canonicalize_folder(&folder)?;
                remove_folder(&file, &canon)?;
                println!("Removed: {}", canon.display());
                Ok(())
            }
            WatchCmd::List => {
                let file = watch_file_path()?;
                list_folders(&file)?;
                Ok(())
            }
        },
    }
}

/* ---------- helpers: sibling bin launchers ---------- */

fn sibling_dir() -> Result<PathBuf> {
    let exe = env::current_exe().context("current_exe")?;
    Ok(exe.parent().unwrap_or_else(|| std::path::Path::new(".")).to_path_buf())
}

fn sibling_path(bin: &str) -> PathBuf {
    let mut p = sibling_dir().unwrap_or_else(|_| PathBuf::from("."));
    #[cfg(windows)]
    { p.push(format!("{bin}.exe")); }
    #[cfg(not(windows))]
    { p.push(bin); }
    p
}

fn sibling_cmd(bin: &str) -> Result<Command> {
    let path = sibling_path(bin);
    Ok(Command::new(path))
}

fn run_sibling<S: AsRef<str>>(bin: &str, args: &[S]) -> Result<()> {
    let mut cmd = sibling_cmd(bin)?;
    for a in args { cmd.arg(a.as_ref()); }
    status_passthrough(cmd)
}

fn status_passthrough(mut cmd: Command) -> Result<()> {
    cmd.stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let status = cmd.status().with_context(|| format!("launch {:?}", cmd))?;
    if status.success() { Ok(()) } else { anyhow::bail!("child exited with {}", status) }
}

/* ---------- verify implementation (MAC-only, no decrypt) ---------- */

fn read_password(prompt: &str) -> Result<String> {
    if atty::is(atty::Stream::Stdin) {
        let pw = rpassword::prompt_password(prompt)?;
        Ok(pw)
    } else {
        // read one line from stdin
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        Ok(s.trim_end_matches(&['\r','\n'][..]).to_string())
    }
}

fn cmd_verify(vault_path: &str) -> Result<()> {
    let mut f = File::open(vault_path).with_context(|| format!("open {}", vault_path))?;

    // Header (61) + Tag (32)
    let mut hdr = [0u8; SARX_HEADER_BYTES];
    f.read_exact(&mut hdr).context("read header")?;
    let (header, header_raw) = VaultHeader::decode_with_raw(&hdr).context("decode header")?;

    let mut tag_file = [0u8; SARX_TAG_BYTES];
    f.read_exact(&mut tag_file).context("read tag")?;

    // Size & CT extent
    let meta = f.metadata()?;
    let total_len = meta.len();
    if total_len < (SARX_HEADER_BYTES + SARX_TAG_BYTES) as u64 {
        anyhow::bail!("invalid vault (too small)");
    }
    let clen = (total_len as usize) - (SARX_HEADER_BYTES + SARX_TAG_BYTES);
    let ct_start = (SARX_HEADER_BYTES + SARX_TAG_BYTES) as u64;

    // Password → derive k_stream_len and k_mac32 with Argon2id header params
    if header.kdf_id != 2 { anyhow::bail!("unsupported kdf_id (expected Argon2id v1.3)"); }
    if !(1..=10).contains(&header.t_cost) { anyhow::bail!("t_cost out of range"); }
    if !(10..=24).contains(&header.m_cost) { anyhow::bail!("m_cost out of range"); }
    if !(1..=4).contains(&header.lanes) { anyhow::bail!("lanes out of range"); }

    let password = read_password("Password: ")?;
    let pass_bytes = password.as_bytes().len();
    let k_stream_len = ((pass_bytes + 31) & !31).max(32);
    let okm_len = k_stream_len + 32;

    let mut okm = vec![0u8; okm_len];
    {
        use argon2::{Argon2, Params, Algorithm, Version};
        let mem_kib: u32 = 1u32 << header.m_cost;
        let params = Params::new(mem_kib, header.t_cost.into(), header.lanes.into(), Some(okm_len))
            .expect("argon2 params");
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        a2.hash_password_into(password.as_bytes(), &header.salt32, &mut okm)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }
    let (_k_stream, k_mac) = okm.split_at(k_stream_len);
    let mut k_mac32 = [0u8; 32];
    k_mac32.copy_from_slice(&k_mac[..32]);

    // MAC over domain || header_raw || len_le || ciphertext
    let mut mac = blake3::Hasher::new_keyed(&k_mac32);
    mac.update(b"SARX2DU-MAC-v1");
    mac.update(&header_raw);
    mac.update(&(clen as u64).to_le_bytes());

    f.seek(SeekFrom::Start(ct_start))?;
    let mut buf = vec![0u8; 16 * 1024 * 1024];
    let mut left = clen;
    while left > 0 {
        let n = left.min(buf.len());
        f.read_exact(&mut buf[..n])?;
        mac.update(&buf[..n]);
        left -= n;
    }

    let mut tag_calc = [0u8; 32];
    mac.finalize_xof().fill(&mut tag_calc);

    okm.zeroize();
    drop(f);

    if ConstantTimeEq::ct_eq(&tag_calc[..], &tag_file[..]).unwrap_u8() == 1 {
        println!("OK: MAC verified.");
        Ok(())
    } else {
        anyhow::bail!("FAIL: MAC mismatch (wrong password or corrupted file).")
    }
}

fn watch_file_path() -> anyhow::Result<PathBuf> {
    let mut home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    home.push(".sarx_watchfolders");
    Ok(home)
}

fn canonicalize_folder(folder: &str) -> anyhow::Result<PathBuf> {
    let canon = std::fs::canonicalize(folder)
        .map_err(|_| anyhow::anyhow!("Not a directory: {}", folder))?;
    if !canon.is_dir() {
        Err(anyhow::anyhow!("Not a directory: {}", canon.display()))
    } else {
        Ok(canon)
    }
}

fn read_watch_folders(file: &Path) -> Vec<PathBuf> {
    if let Ok(f) = std::fs::File::open(file) {
        std::io::BufReader::new(f)
            .lines()
            .filter_map(|l| l.ok())
            .filter_map(|l| {
                let p = PathBuf::from(l);
                if p.is_dir() { Some(p) } else { None }
            })
            .collect()
    } else {
        Vec::new()
    }
}

fn add_folder(file: &Path, folder: &Path) -> anyhow::Result<()> {
    let mut folders = read_watch_folders(file);
    if !folders.iter().any(|p| p == folder) {
        folders.push(folder.to_path_buf());
        write_watch_folders(file, &folders)?;
    }
    Ok(())
}

fn remove_folder(file: &Path, folder: &Path) -> anyhow::Result<()> {
    let mut folders = read_watch_folders(file);
    let before = folders.len();
    folders.retain(|p| p != folder);
    if folders.len() < before {
        write_watch_folders(file, &folders)?;
    }
    Ok(())
}

fn write_watch_folders(file: &Path, folders: &[PathBuf]) -> anyhow::Result<()> {
    let parent = file.parent().ok_or_else(|| anyhow::anyhow!("Invalid file path"))?;
    std::fs::create_dir_all(parent)?;
    let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(file)?;
    for p in folders {
        writeln!(f, "{}", p.display())?;
    }
    Ok(())
}

fn list_folders(file: &Path) -> anyhow::Result<()> {
    let folders = read_watch_folders(file);
    if folders.is_empty() {
        println!("(no folders configured)");
    } else {
        println!("Watched folders:");
        for p in folders {
            println!("{}", p.display());
        }
    }
    Ok(())
}
