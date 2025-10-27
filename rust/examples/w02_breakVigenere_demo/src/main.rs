// break_vigenere.rs
// Interactive Vigenere breaker: Kasiski -> chi-sq column solve -> tetragram scoring
// Usage: cargo run --release
//
// Paste ciphertext at the prompt and press Ctrl+D (Unix) or Ctrl+Z then Enter (Windows).
//
// Note: table of quadgrams here is a seed. For best accuracy on short text, replace it
// with a comprehensive quadgram log-probability table.

use std::collections::HashMap;
use std::io::{self, Read, Write};

const EN_FREQ: [f64; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094,
    0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929,
    0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,
    0.01974, 0.00074,
];

fn main() {
    // 1) Interactive input
    print!("Input the ciphertext (paste then press Ctrl+D on Unix or Ctrl+Z then Enter on Windows):\n");
    io::stdout().flush().expect("flush failed");

    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("Failed to read stdin");

    let cipher = clean_text(&input);
    if cipher.len() < 6 {
        eprintln!("Ciphertext too short after cleaning: length {}", cipher.len());
        return;
    }
    println!("\nCiphertext length (letters only): {}\n", cipher.len());

    // Optional: force key length
    print!("(Optional) Force key length? Press Enter to skip, or type a number: ");
    io::stdout().flush().unwrap();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
    let forced_k: Option<usize> = buf.trim().parse::<usize>().ok();

    // 2) Kasiski-ish repeats
    let min_ngram = 3usize;
    let repeats = find_repeats(&cipher, min_ngram);

    if repeats.is_empty() {
        println!("No repeated {}-grams found. Try smaller n or provide more ciphertext.", min_ngram);
    } else {
        println!("Found repeated {}-grams (showing some):", min_ngram);
        let mut shown = 0;
        for (ng, pos) in repeats.iter() {
            if pos.len() > 1 && shown < 20 {
                println!("  {} -> positions {:?}", ng, pos);
                shown += 1;
            }
        }
        println!();
    }

    // 3) distances & factor frequencies
    let distances = collect_distances(&repeats);
    if !distances.is_empty() {
        println!("Some distances between repeated sequences (showing up to 40):");
        for d in distances.iter().take(40) {
            print!("{} ", d);
        }
        println!("\n");

        let factor_counts = factor_frequencies(&distances);
        println!("Most common factors (candidate key lengths):");
        let mut factors: Vec<_> = factor_counts.into_iter().collect();
        factors.sort_by(|a, b| b.1.cmp(&a.1));
        for (f, cnt) in factors.iter().take(12) {
            println!("  {:2} -> count {}", f, cnt);
        }
        println!();
    } else {
        println!("No distances found from repeats.\n");
    }

    // 4) Candidate list
    let mut candidates: Vec<usize> = Vec::new();
    if let Some(k) = forced_k {
        if k > 0 {
            candidates.push(k);
        }
    } else {
        // gather from factor counts (2..=40)
        let mut factor_counts = factor_frequencies(&distances);
        let mut factors: Vec<_> = factor_counts.into_iter().collect();
        factors.sort_by(|a, b| b.1.cmp(&a.1));
        for (f, _cnt) in factors.iter().take(8) {
            if *f > 1 && *f <= 60 {
                candidates.push(*f);
            }
        }
        // fill with 1..12
        for k in 1..13 {
            if !candidates.contains(&k) {
                candidates.push(k);
            }
        }
    }
    candidates.sort();
    candidates.dedup();

    println!("Trying candidate key lengths: {:?}\n", candidates);

    // 5) Solve each candidate with chi-sq, then score plain with quadgrams
    let quad_table = tetragram_table(); // actually quadgrams
    let mut results: Vec<(usize, String, f64, f64, String)> = Vec::new();
    // (klen, key, chi_score (lower better), fitness (higher better), plaintext)

    for &klen in candidates.iter() {
        if klen == 0 { continue; }
        let (key, chi_score, plain) = try_key_length(&cipher, klen);
        let fitness = tetragram_score(&plain, &quad_table);
        results.push((klen, key, chi_score, fitness, plain));
    }

    // sort primarily by fitness descending, tie-break by chi-score ascending
    results.sort_by(|a, b| {
        b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
    });

    // print top results
    println!("Top candidate decryptions (sorted by tetragram fitness):\n");
    for (klen, key, chi, fit, plain) in results.iter().take(10) {
        println!("Key len {:2} | chi-sq {:8.2} | fitness {:8.2} | key: {}", klen, chi, fit, key);
        println!("Plaintext:\n{}\n", plain);
    }

    if results.is_empty() {
        println!("No candidate decryptions generated. Try longer ciphertext or different parameters.");
    } else {
        println!("If the correct plaintext isn't visible, try forcing a key length when prompted,");
        println!("or replace the tetragram table with a more complete quadgram frequency table.");
    }
}

/// Clean input: keep only A-Z and uppercase
fn clean_text(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Find repeated n-grams of lengths n_min..=max_n
fn find_repeats(text: &str, n_min: usize) -> HashMap<String, Vec<usize>> {
    let mut map: HashMap<String, Vec<usize>> = HashMap::new();
    let max_n = 6usize;
    let len = text.len();
    for n in n_min..=max_n {
        if n > len { break; }
        for i in 0..=(len - n) {
            let ng = text[i..i + n].to_string();
            map.entry(ng).or_default().push(i);
        }
    }
    map.retain(|_k, v| v.len() > 1);
    map
}

/// Collect pairwise distances between repeated occurrences
fn collect_distances(repeats: &HashMap<String, Vec<usize>>) -> Vec<usize> {
    let mut distances = Vec::new();
    for (_ng, pos) in repeats.iter() {
        for i in 0..pos.len() {
            for j in (i + 1)..pos.len() {
                let dist = pos[j] - pos[i];
                if dist > 0 {
                    distances.push(dist);
                }
            }
        }
    }
    distances.sort();
    distances
}

/// Factor distances and count factor frequencies (2..=60)
fn factor_frequencies(distances: &[usize]) -> HashMap<usize, usize> {
    let mut counts: HashMap<usize, usize> = HashMap::new();
    for &d in distances.iter() {
        for f in 2..=60 {
            if d % f == 0 {
                *counts.entry(f).or_default() += 1;
            }
        }
    }
    counts
}

/// For given key length, compute best shift per column via chi-sq and return key, total chi score, plaintext
fn try_key_length(cipher: &str, klen: usize) -> (String, f64, String) {
    let mut key = String::new();
    let mut total_score = 0.0;
    let bytes = cipher.as_bytes();
    for col in 0..klen {
        let mut col_letters: Vec<u8> = Vec::new();
        let mut i = col;
        while i < bytes.len() {
            col_letters.push(bytes[i]);
            i += klen;
        }
        let (best_shift, best_score) = best_shift_for_column(&col_letters);
        let key_char = ((best_shift as u8) + b'A') as char;
        key.push(key_char);
        total_score += best_score;
    }
    let plain = vigenere_decrypt(cipher, &key);
    (key, total_score, plain)
}

/// Chi-squared best shift for a column
fn best_shift_for_column(col: &Vec<u8>) -> (usize, f64) {
    let mut counts = [0usize; 26];
    for &b in col.iter() {
        if b'A' <= b && b <= b'Z' {
            counts[(b - b'A') as usize] += 1;
        }
    }
    let n: usize = counts.iter().sum();
    if n == 0 { return (0usize, std::f64::INFINITY); }

    let mut best_shift = 0usize;
    let mut best_score = std::f64::INFINITY;

    for shift in 0..26 {
        let mut obs = [0f64; 26];
        for i in 0..26 {
            let plain_idx = (26 + i as isize - shift as isize) as usize % 26;
            obs[plain_idx] += counts[i] as f64;
        }
        let mut chi = 0.0f64;
        for i in 0..26 {
            let expected = EN_FREQ[i] * (n as f64);
            if expected > 0.0 {
                let diff = obs[i] - expected;
                chi += diff * diff / expected;
            }
        }
        if chi < best_score {
            best_score = chi;
            best_shift = shift;
        }
    }
    (best_shift, best_score)
}

/// Vigenere decrypt uppercase ciphertext with uppercase key
fn vigenere_decrypt(cipher: &str, key: &str) -> String {
    let mut out = String::with_capacity(cipher.len());
    let kb = key.as_bytes();
    let klen = kb.len();
    if klen == 0 { return String::new(); }

    for (i, &cb) in cipher.as_bytes().iter().enumerate() {
        if cb >= b'A' && cb <= b'Z' {
            let shift = (kb[i % klen] - b'A') as i32;
            // cb is already u8 (not a reference), so don't deref it
            let p = ((cb - b'A') as i32 - shift + 26) % 26;
            out.push((b'A' + p as u8) as char);
        } else {
            out.push(cb as char);
        }
    }
    out
}


/// A seeded tetragram / quadgram log-probability table (uppercase). Replace with a full table for best results.
fn tetragram_table() -> HashMap<[u8;4], f64> {
    let mut t = HashMap::new();
    // These values are illustrative log10 probabilities (negative). In practice use precomputed log-probs.
    // Common English 4-grams (seed). Add/replace with a full list for production accuracy.
    let entries = [
        ("TION", -3.0), ("THER", -3.1), ("HERE", -3.2), ("THAT", -3.2),
        ("OFTH", -3.3), ("FTHE", -3.3), ("INTH", -3.3), ("ATIO", -3.4),
        ("NDTH", -3.5), ("TTHE", -3.5), ("MENT", -3.6), ("IONS", -3.6),
        ("EDTH", -3.7), ("EVER", -3.7), ("THE ", -5.0), // space not present, but kept as seed
        ("WITH", -3.5), ("ESTH", -3.8), ("HERE", -3.2), ("OFTHE", -2.8) // note: "OFTHE" is 5-char, will be truncated
    ];
    for &(s, v) in entries.iter() {
        let s4 = {
            let mut buf = [b'A'; 4];
            let bytes = s.as_bytes();
            for i in 0..4 {
                buf[i] = if i < bytes.len() { bytes[i].to_ascii_uppercase() } else { b'A' };
            }
            buf
        };
        t.insert(s4, v);
    }
    // A couple of very common 4-grams
    t.insert(*b"TION", -3.0);
    t.insert(*b"THER", -3.1);
    t.insert(*b"THES", -3.6);
    t.insert(*b"ERE ", -5.0); // spaces won't match but keep seed
    t
}

/// Compute tetragram/quadgram score (higher = better). Use floor for unseen grams.
fn tetragram_score(text: &str, table: &HashMap<[u8;4], f64>) -> f64 {
    let bytes = text.as_bytes();
    if bytes.len() < 4 { return std::f64::NEG_INFINITY; }
    let floor = -8.0; // penalty for unseen tetragrams (tweak as needed)
    let mut s = 0.0;
    for i in 0..=bytes.len()-4 {
        let slice = &bytes[i..i+4];
        if slice.iter().all(|&b| b'A' <= b && b <= b'Z') {
            let mut key = [0u8;4];
            key.copy_from_slice(slice);
            s += *table.get(&key).unwrap_or(&floor);
        } else {
            // penalize non-letter n-grams mildly
            s += floor;
        }
    }
    s
}
