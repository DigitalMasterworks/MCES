use anyhow::Result;
use blake3::Hasher as Blake3;
use sarx::sarx::thermo_harden_okm;
use std::time::Instant;

fn kdf_sarx_okm(password: &str, salt32: &[u8; 32], t_cost: u32, m_cost: u32, lanes: u32, use_thermo: bool) -> Vec<u8> {
    let pass_bytes = password.as_bytes().len();
    let k_stream_len = ((pass_bytes + 31) & !31).max(32);
    let okm_len = k_stream_len + 32;
    let mut okm = vec![0u8; okm_len];

    {
        use argon2::{Argon2, Params, Algorithm, Version};
        let mem_kib: u32 = 1u32 << m_cost;
        let params = Params::new(mem_kib, t_cost, lanes, Some(okm_len)).unwrap();
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        a2.hash_password_into(password.as_bytes(), salt32, &mut okm)
            .expect("argon2");
    }

    if use_thermo {
        thermo_harden_okm(&mut okm);
    }

    okm
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: kdf_guess_loop <guesses> <mode: base|thermo>");
        std::process::exit(1);
    }
    let guesses: usize = args[1].parse()?;
    let mode = &args[2];
    let use_thermo = match mode.as_str() {
        "base" => false,
        "thermo" => true,
        _ => {
            eprintln!("mode must be 'base' or 'thermo'");
            std::process::exit(1);
        }
    };

    // Fixed “wrong” password, we just want cost per guess
    let password = "this is a fake password guess";
    // Deterministic salt for repeatability
    let mut salt32 = [0u8; 32];
    {
        let mut h = Blake3::new();
        h.update(b"KDF-GUESS-SALT");
        h.update(password.as_bytes());
        h.finalize_xof().fill(&mut salt32);
    }

    let t_cost = 3;
    let m_cost = 17; // 128 MiB
    let lanes = 1;

    let start = Instant::now();
    let mut sink = 0u8;
    for i in 0..guesses {
        // vary password slightly so Argon2 doesn't get silly
        let pw = format!("{password}-{i}");
        let okm = kdf_sarx_okm(&pw, &salt32, t_cost, m_cost, lanes, use_thermo);
        // tiny sink so compiler can't optimize away
        for b in &okm {
            sink ^= *b;
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    std::hint::black_box(sink);

    println!(
        "Mode={} guesses={} elapsed={:.6} s (≈{:.6} s/guess)",
        mode,
        guesses,
        elapsed,
        elapsed / guesses as f64
    );
    Ok(())
}