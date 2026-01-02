//! Built-in database of known WUD disc keys
//! 
//! This allows automatic key lookup based on game product code.
//! Keys are publicly available in various community databases.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};
use serde::Deserialize;

// Known URLs for Wii U title keys
const KEY_URLS: &[&str] = &[
    "http://wiiutitlekeys.ddns.net/json", // Common community database (JSON)
    "https://titlekeys.ovh/json",         // Mirror (JSON)
];

/// Database of known disc keys, indexed by product code (e.g., "ANXP")
/// We use RwLock to allow updating it at runtime.
static DISC_KEYS: LazyLock<RwLock<HashMap<String, String>>> = LazyLock::new(|| {
    let m = HashMap::new();
    // Keys are no longer hardcoded for safety.
    // Use the "Update Keys from Web" feature in the GUI to fetch them.
    RwLock::new(m)
});

/// Fetch keys from all known URLs
pub fn update_keys() -> Result<usize, String> {
    let mut total_added = 0;
    let mut errors = Vec::new();

    for url in KEY_URLS {
        match fetch_keys_from_url(url) {
            Ok(count) => {
                total_added += count;
            }
            Err(e) => {
                errors.push(format!("Failed {}: {:?}", url, e));
            }
        }
    }

    if total_added == 0 && !errors.is_empty() {
        return Err(errors.join("; "));
    }

    Ok(total_added)
}
fn fetch_keys_from_url(url: &str) -> std::result::Result<usize, FetchError> {
    println!("Fetching keys from: {}", url);
    
    // User-Agent is often required by some servers
    let client = reqwest::blocking::Client::builder()
        .user_agent("Kairo/0.1.0")
        .build()
        .map_err(FetchError::Request)?;
        
    let resp = client.get(url).send().map_err(FetchError::Request)?;
    let text = resp.text().map_err(FetchError::Request)?;
    
    // Try Parsing as JSON first (Robust Mode)
    // Parse as general Value to handle potential schema mismatches in individual entries
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
        if let Some(entries) = json.as_array() {
            let mut count = 0;
            let mut db = DISC_KEYS.write().unwrap();
            
            for entry in entries {
                // Manually extract fields we care about
                let title_id = entry.get("titleID").and_then(|v| v.as_str());
                let title_key = entry.get("titleKey").and_then(|v| v.as_str());
                
                if let (Some(tid), Some(tkey)) = (title_id, title_key) {
                    if tid.len() == 16 && tkey.len() == 32 {
                        db.insert(tid.to_uppercase(), tkey.to_string());
                        count += 1;
                    }
                }
            }
            if count > 0 {
                return Ok(count);
            }
        }
    }
    
    // Try Parsing as Pipe/Text format
    // Format usually: TitleID|Key|Name...
    let mut count = 0;
    let mut db = DISC_KEYS.write().unwrap();
    
    for line in text.lines() {
        let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
        if parts.len() >= 2 {
            let id = parts[0];
            let key = parts[1];
            if id.len() == 16 && key.len() == 32 {
                db.insert(id.to_uppercase(), key.to_string());
                count += 1;
            }
        }
    }
    
    if count > 0 {
        Ok(count)
    } else {
        Err(FetchError::NoKeysFound)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum FetchError {
    Request(reqwest::Error),
    Parse(String),
    NoKeysFound,
}
/// Extract product code from WUD header
pub fn extract_product_code(header: &[u8]) -> Option<String> {
    if header.len() < 10 { return None; }
    if &header[0..6] != b"WUP-P-" { return None; }
    let code = String::from_utf8_lossy(&header[6..10]).to_string();
    if code.chars().all(|c| c.is_ascii_alphanumeric()) { Some(code) } else { None }
}

/// Extract Title ID from WUD header (if possible) or Ticket
/// Note: WUD header at offset 0 usually contains Game Partition info?
/// WUD common header:
/// 0x00: "WUP-"
/// Actually, Disc Header (at start of WUD) has Title ID?
/// Usually we rely on Product Code "WUP-P-XXXX".
/// But wait, Ticket has Title ID.
pub fn lookup_disc_key(product_code: &str) -> Option<String> {
    let db = DISC_KEYS.read().unwrap();
    db.get(product_code).cloned()
}

/// Load keys from a local text file (e.g. keys.txt)
/// Format: HEX_KEY (32 chars) # Comment
/// OR: TITLE_ID # HEX_KEY # Name
pub fn load_keys_from_file<P: AsRef<std::path::Path>>(path: P) -> std::result::Result<usize, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut count = 0;
    let mut db = DISC_KEYS.write().unwrap();
    
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        
        let parts: Vec<&str> = line.split(|c| c == '#' || c == '|' || c == '=').map(|s| s.trim()).collect();
        
        for part in &parts {
            if part.len() == 32 && part.chars().all(|c| c.is_ascii_hexdigit()) {
                // Found a key. Do we have an Identifier (Title ID or Product Code)?
                
                // 1. Look for Title ID (16 hex chars)
                if let Some(tid) = parts.iter().find(|p| p.len() == 16 && p.chars().all(|c| c.is_ascii_hexdigit())) {
                     db.insert(tid.to_uppercase(), part.to_string());
                     count += 1;
                }
                // 2. Look for Product Code (4 chars, alphanumeric) e.g. ANXP
                else if let Some(code) = parts.iter().find(|p| p.len() == 4 && p.chars().all(|c| c.is_ascii_alphanumeric())) {
                     db.insert(code.to_string(), part.to_string());
                     count += 1;
                }
            }
        }
    }
    
    Ok(count)
}

/// Look up by Title ID (16 char hex)
#[allow(dead_code)]
pub fn lookup_by_title_id(title_id: &str) -> Option<String> {
    let db = DISC_KEYS.read().unwrap();
    db.get(&title_id.to_uppercase()).cloned()
}

/// Parse a hex string into a 16-byte key
pub fn parse_hex_key(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 { return None; }
    let mut key = [0u8; 16];
    for i in 0..16 {
        key[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16).ok()?;
    }
    Some(key)
}

/// Extract Title ID candidates from WUD header (heuristic scan)
/// Scans for patterns common in Wii U identifiers (e.g., 00 05 00 XX)
pub fn extract_title_candidates(header: &[u8]) -> Vec<String> {
    let mut candidates = Vec::new();
    // Scan up to 64KB
    let limit = std::cmp::min(header.len(), 65536);
    for i in 0..limit.saturating_sub(8) {
        // Check for 00 05 00 prefix (Big Endian) which denotes a Wii U Title ID
        if header[i] == 0x00 && header[i+1] == 0x05 && header[i+2] == 0x00 {
            // Found candidate. Convert to hex string.
            let mut tid_hex = String::new();
            for b in &header[i..i+8] {
                use std::fmt::Write;
                write!(&mut tid_hex, "{:02X}", b).unwrap();
            }
            candidates.push(tid_hex);
        }
    }
    candidates
}

/// Get game name (legacy support for hardcoded codes)
pub fn get_game_name(product_code: &str) -> Option<&'static str> {
    match product_code {
         "ANXP" | "ANXE" | "ANXJ" => Some("Wii Party U"),
         _ => None,
    }
}

/// Get region
pub fn get_region(product_code: &str) -> &'static str {
    match product_code.chars().last() {
        Some('P') => "EUR",
        Some('E') => "USA",
        Some('J') => "JPN",
        _ => "Unknown",
    }
}
