//! Built-in database of known WUD disc keys
//! 
//! This allows automatic key lookup based on game product code.
//! Keys are publicly available in various community databases.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};
use serde::Deserialize;

// Known URLs for Wii U keys
const KEY_URLS: &[&str] = &[
    // GitHub Gist with WUD Disc Keys (format: KEY # Game Name [REGION, WUD])
    "https://gist.githubusercontent.com/xXPhenomXx/093b352723ec51644453a9528a8dc87e/raw",
    "https://gist.githubusercontent.com/ClassicOldSong/024b2176d5a413f499db6bc26d272943/raw",
    // NUS/eShop databases (fallback, less useful for WUD)
    "http://wiiutitlekeys.ddns.net/json",
    "https://titlekeys.ovh/json",
];

// Myrient Redump has individual key files per game - we fetch on-demand
const MYRIENT_BASE_URL: &str = "https://myrient.erista.me/files/Redump/Nintendo%20-%20Wii%20U%20-%20Disc%20Keys/";

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
    
    // Try Parsing as Pipe/Text format (TitleID|Key|Name...)
    // Or Gist format: KEY # Game Name [REGION, WUD/NUS]
    let mut count = 0;
    let mut db = DISC_KEYS.write().unwrap();
    
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        
        // Gist format: KEY # Game Name [REGION, WUD]
        // We only want WUD keys, not NUS keys
        if line.contains("[") && line.contains("]") {
            // Check if this is a WUD key
            if line.contains("WUD]") || line.contains("WUD,") {
                // Extract the key (first 32 hex chars)
                let key_part = line.split('#').next().unwrap_or("").trim();
                if key_part.len() == 32 && key_part.chars().all(|c| c.is_ascii_hexdigit()) {
                    // Extract game name from comment
                    if let Some(comment) = line.split('#').nth(1) {
                        let comment = comment.trim();
                        // Store by game name (normalized) for fuzzy matching
                        // Also try to extract region from [EUR, WUD] pattern
                        db.insert(format!("WUD:{}", comment.to_uppercase()), key_part.to_string());
                        count += 1;
                    }
                }
            }
            continue;
        }
        
        // Pipe format: TitleID|Key|Name...
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

/// Fetch key directly from Myrient Redump for a specific game
/// Returns the 16-byte key as hex string if found
pub fn fetch_key_from_myrient(game_name: &str, region: &str) -> Option<String> {
    // Myrient uses format: "Game Name (Region) (Languages).zip"
    // We need to search the directory listing or try common patterns
    
    let region_name = match region {
        "EUR" => "Europe",
        "USA" => "USA",
        "JPN" => "Japan",
        _ => return None,
    };
    
    // Try common filename patterns
    let patterns = vec![
        format!("{} ({}) ", game_name, region_name),
        format!("{} ({})", game_name, region_name),
    ];
    
    // Fetch directory listing
    let client = match reqwest::blocking::Client::builder()
        .user_agent("Kairo/0.1.0")
        .build() {
            Ok(c) => c,
            Err(_) => return None,
        };
    
    let listing_url = MYRIENT_BASE_URL;
    let listing = match client.get(listing_url).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return None,
    };
    
    // Find matching filename in listing
    for pattern in &patterns {
        let pattern_upper = pattern.to_uppercase();
        for line in listing.lines() {
            if line.to_uppercase().contains(&pattern_upper) && line.contains(".zip") {
                // Extract filename from href
                if let Some(start) = line.find("href=\"") {
                    let rest = &line[start + 6..];
                    if let Some(end) = rest.find("\"") {
                        let filename = &rest[..end];
                        // Fetch the ZIP
                        let zip_url = format!("{}{}", MYRIENT_BASE_URL, filename);
                        println!("   Fetching key from Myrient: {}", filename);
                        
                        if let Ok(resp) = client.get(&zip_url).send() {
                            if let Ok(bytes) = resp.bytes() {
                                // ZIP contains a single .bin file with 16 bytes
                                if let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(bytes)) {
                                    if let Ok(mut file) = archive.by_index(0) {
                                        let mut key_bytes = vec![0u8; 16];
                                        use std::io::Read;
                                        if file.read_exact(&mut key_bytes).is_ok() {
                                            let key_hex: String = key_bytes.iter()
                                                .map(|b| format!("{:02x}", b))
                                                .collect();
                                            
                                            println!("   Found key: {}", key_hex);
                                            
                                            // Store in DB for future lookups
                                            if let Ok(mut db) = DISC_KEYS.write() {
                                                db.insert(
                                                    format!("WUD:{} [{}, WUD]", game_name.to_uppercase(), region),
                                                    key_hex.clone()
                                                );
                                            }
                                            
                                            return Some(key_hex);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    None
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
/// Lookup disc key using product code and/or filename
/// Game name is extracted from filename (no hardcoded names!)
pub fn lookup_disc_key_with_filename(product_code: &str, filename: Option<&str>) -> Option<String> {
    let db = DISC_KEYS.read().unwrap();
    
    // 1. Direct lookup by product code
    if let Some(key) = db.get(product_code) {
        return Some(key.clone());
    }
    
    // 2. Try to find a WUD key using filename
    // Extract game name from filename (e.g., "Wii Party U (Europe).wud" -> "Wii Party U")
    if let Some(fname) = filename {
        // Remove extension and clean up
        let name = fname
            .trim_end_matches(".wud")
            .trim_end_matches(".wux")
            .trim_end_matches(".WUD")
            .trim_end_matches(".WUX");
        
        // Extract core game name: everything before first parenthesis
        // "Wii Party U (Europe) (Rev 1)" -> "Wii Party U"
        let core_name: &str = if let Some(paren_pos) = name.find('(') {
            name[..paren_pos].trim()
        } else {
            name.trim()
        };
        
        if !core_name.is_empty() {
            let region = get_region(product_code);
            let game_upper = core_name.to_uppercase();
            
            println!("   Searching for: '{}' [{}]", core_name, region);
            
            // Only match with correct region - don't fallback to other regions (keys are region-specific!)
            for (key_name, key_value) in db.iter() {
                if key_name.starts_with("WUD:") && 
                   key_name.to_uppercase().contains(&game_upper) &&
                   key_name.contains("WUD]") {
                    // Check if region matches
                    let has_matching_region = 
                        (region == "EUR" && key_name.contains("EUR,")) ||
                        (region == "USA" && key_name.contains("USA,")) ||
                        (region == "JPN" && key_name.contains("JPN,"));
                    
                    if has_matching_region {
                        println!("   Matched: {}", key_name);
                        return Some(key_value.clone());
                    }
                }
            }
            
            // Fallback: try Myrient Redump (has more complete regional keys)
            println!("   Not found in Gist DB - trying Myrient Redump...");
            drop(db); // Release read lock before network call
            if let Some(key) = fetch_key_from_myrient(core_name, region) {
                return Some(key);
            }
            
            println!("   ⚠️ No {} key found for this game.", region);
        }
    }
    
    None
}

/// Simple lookup by product code only (legacy)
pub fn lookup_disc_key(product_code: &str) -> Option<String> {
    lookup_disc_key_with_filename(product_code, None)
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

/// Get region from product code (last character)
pub fn get_region(product_code: &str) -> &'static str {
    match product_code.chars().last() {
        Some('P') => "EUR",
        Some('E') => "USA",
        Some('J') => "JPN",
        _ => "Unknown",
    }
}
