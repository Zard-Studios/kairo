//! WUP Packer - Convert code/content/meta to installable WUP format
//!
//! This module implements the NUSPacker functionality in pure Rust,
//! generating .app, .h3, title.tmd, title.tik files for WUP Installer.

use std::fs::{self, File};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use sha1::{Sha1, Digest};

/// Wii U Common Key (must be provided by user, fetched from disc_keys)
/// Used to encrypt the Title Key in the ticket.

/// TMD Signature Type: RSA-2048 + SHA-1
const TMD_SIGNATURE_TYPE: u32 = 0x00010001;

/// Content type flags
const CONTENT_TYPE_NORMAL: u16 = 0x0001;
const CONTENT_TYPE_HASHED: u16 = 0x0002;

/// Block size for content encryption (64KB)
const CONTENT_BLOCK_SIZE: usize = 0x10000;

/// Hash block size for H3 generation
const HASH_BLOCK_SIZE: usize = 0x400000; // 4MB

//=============================================================================
// TMD (Title Metadata) Structures
//=============================================================================

/// TMD Header - appears at the start of title.tmd
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TmdHeader {
    pub signature_type: u32,
    pub signature: [u8; 256],
    pub padding: [u8; 60],
    pub issuer: [u8; 64],
    pub version: u8,
    pub ca_crl_version: u8,
    pub signer_crl_version: u8,
    pub reserved1: u8,
    pub system_version: u64,
    pub title_id: u64,
    pub title_type: u32,
    pub group_id: u16,
    pub save_data_size: u32,
    pub srl_private_save_size: u32,
    pub reserved2: u32,
    pub srl_flag: u8,
    pub reserved3: [u8; 49],
    pub access_rights: u32,
    pub title_version: u16,
    pub num_contents: u16,
    pub boot_index: u16,
    pub minor_version: u16,
}

impl Default for TmdHeader {
    fn default() -> Self {
        Self {
            signature_type: 0,
            signature: [0u8; 256],
            padding: [0u8; 60],
            issuer: [0u8; 64],
            version: 0,
            ca_crl_version: 0,
            signer_crl_version: 0,
            reserved1: 0,
            system_version: 0,
            title_id: 0,
            title_type: 0,
            group_id: 0,
            save_data_size: 0,
            srl_private_save_size: 0,
            reserved2: 0,
            srl_flag: 0,
            reserved3: [0u8; 49],
            access_rights: 0,
            title_version: 0,
            num_contents: 0,
            boot_index: 0,
            minor_version: 0,
        }
    }
}

/// Content Info Record - hash of content records
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct ContentInfoRecord {
    pub index_offset: u16,
    pub command_count: u16,
    pub sha256_hash: [u8; 32],
}

/// Content Chunk Record - metadata for each .app file
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct ContentChunkRecord {
    pub content_id: u32,
    pub index: u16,
    pub content_type: u16,
    pub size: u64,
    pub sha256_hash: [u8; 32],
}

//=============================================================================
// Ticket Structures  
//=============================================================================

/// Ticket header - appears at the start of title.tik
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TicketHeader {
    pub signature_type: u32,
    pub signature: [u8; 256],
    pub padding: [u8; 60],
    pub issuer: [u8; 64],
    pub ecdh: [u8; 60],
    pub version: u8,
    pub ca_crl_version: u8,
    pub signer_crl_version: u8,
    pub title_key: [u8; 16],
    pub reserved1: u8,
    pub ticket_id: u64,
    pub console_id: u32,
    pub title_id: u64,
    pub reserved2: u16,
    pub title_version: u16,
    pub permitted_titles: u32,
    pub permit_mask: u32,
    pub export_allowed: u8,
    pub common_key_index: u8,
    pub reserved3: [u8; 48],
    pub content_access_permissions: [u8; 64],
    pub padding2: [u8; 2],
    pub limits: [TicketLimit; 8],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct TicketLimit {
    pub limit_type: u32,
    pub limit_value: u32,
}

impl Default for TicketHeader {
    fn default() -> Self {
        Self {
            signature_type: TMD_SIGNATURE_TYPE.to_be(),
            signature: [0u8; 256],
            padding: [0u8; 60],
            issuer: [0u8; 64],
            ecdh: [0u8; 60],
            version: 1,
            ca_crl_version: 0,
            signer_crl_version: 0,
            title_key: [0u8; 16],
            reserved1: 0,
            ticket_id: 0,
            console_id: 0,
            title_id: 0,
            reserved2: 0,
            title_version: 0,
            permitted_titles: 0,
            permit_mask: 0xFFFFFFFF,
            export_allowed: 0,
            common_key_index: 0,
            reserved3: [0u8; 48],
            content_access_permissions: [0xFF; 64],
            padding2: [0u8; 2],
            limits: [TicketLimit::default(); 8],
        }
    }
}

//=============================================================================
//=============================================================================
// Encryption Functions
//=============================================================================

/// Generate a random 16-byte title key
pub fn generate_title_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    // Use system random for security
    if let Ok(mut f) = File::open("/dev/urandom") {
        let _ = f.read_exact(&mut key);
    } else {
        // Fallback: use timestamp-based pseudo-random
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        for i in 0..16 {
            key[i] = ((t >> (i * 4)) & 0xFF) as u8;
        }
    }
    key
}

/// Encrypt title key using AES-128-CBC with common key
/// IV is Title ID padded with zeros
pub fn encrypt_title_key(
    title_key: &[u8; 16],
    common_key: &[u8; 16],
    title_id: u64,
) -> [u8; 16] {
    // IV = Title ID (big endian) + 8 zero bytes
    let mut iv = [0u8; 16];
    iv[0..8].copy_from_slice(&title_id.to_be_bytes());
    
    // AES-128-CBC encryption
    let cipher = Aes128::new(GenericArray::from_slice(common_key));
    
    // XOR with IV
    let mut block = [0u8; 16];
    for i in 0..16 {
        block[i] = title_key[i] ^ iv[i];
    }
    
    // Encrypt
    let mut encrypted = GenericArray::clone_from_slice(&block);
    cipher.encrypt_block(&mut encrypted);
    
    let mut result = [0u8; 16];
    result.copy_from_slice(&encrypted);
    result
}

// Streaming Encryption & Hashing
//=============================================================================

/// Progress callback type (matches extract.rs)
pub type ProgressCallback = std::sync::Arc<std::sync::Mutex<dyn Fn(f32, &str) + Send>>;

/// Process a folder, packing its contents into an .app file using streaming encryption.
/// Returns (size, sha256_hash, sha1_hashes_for_h3)
fn pack_folder_streaming(
    folder_path: &Path, 
    app_path: &Path, 
    title_key: &[u8; 16], 
    content_index: u16,
    progress: Option<&ProgressCallback>
) -> Result<(u64, [u8; 32], Vec<u8>), String> {
    
    // 1. Prepare output file
    let mut app_file = File::create(app_path).map_err(|e| format!("Failed to create .app file: {}", e))?;
    
    // 2. Initialize encryption (AES-128-CBC)
    // IV = content index (big endian) + 14 zero bytes
    let mut iv = [0u8; 16];
    iv[0..2].copy_from_slice(&content_index.to_be_bytes());
    let cipher = Aes128::new(GenericArray::from_slice(title_key));
    let mut prev_block = iv; // CBC chaining state
    
    // 3. Initialize hashing
    let mut sha256 = sha2::Sha256::new(); // Hash of PLAINTEXT data (decrypted)
    let mut current_h3_block = Vec::with_capacity(HASH_BLOCK_SIZE);
    let mut h3_hashes = Vec::new();
    
    // 4. Collect file list recursively to ensure deterministic order
    let mut file_entries = Vec::new();
    collect_files_recursive(folder_path, folder_path, &mut file_entries)?;
    
    // Calculate total size for progress (approximate)
    let total_bytes: u64 = file_entries.iter()
        .map(|(name, size)| 12 + name.len() as u64 + *size)
        .sum();
    let mut processed_bytes = 0u64;
    
    // We need a buffering mechanism because we can only encrypt full 16-byte blocks
    let mut encryption_buffer = Vec::with_capacity(CONTENT_BLOCK_SIZE);
    
    for (rel_path, size) in file_entries {
        // File Header: Name Len (4) + Name + Data Len (8)
        let name_bytes = rel_path.as_bytes();
        let name_len = name_bytes.len() as u32;
        let data_len = size;
        
        let mut header = Vec::new();
        header.extend_from_slice(&name_len.to_be_bytes());
        header.extend_from_slice(name_bytes);
        header.extend_from_slice(&data_len.to_be_bytes());
        
        // Process header
        process_chunk(
            &header, &mut encryption_buffer, &cipher, &mut prev_block, 
            &mut app_file, &mut sha256, &mut current_h3_block, &mut h3_hashes
        )?;
        
        // Process file content streaming
        let mut file = File::open(folder_path.join(&rel_path)).map_err(|e| e.to_string())?;
        let mut buffer = [0u8; 64 * 1024]; // 64KB buffer
        
        loop {
            let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if n == 0 { break; }
            
            process_chunk(
                &buffer[..n], &mut encryption_buffer, &cipher, &mut prev_block, 
                &mut app_file, &mut sha256, &mut current_h3_block, &mut h3_hashes
            )?;
            
            processed_bytes += n as u64;
            if let Some(cb) = progress {
                if processed_bytes % (1024 * 1024 * 10) == 0 { // Update every 10MB
                    let pct = (processed_bytes as f32 / total_bytes as f32) * 100.0;
                    (cb.lock().unwrap())(pct, &format!("Packing {:08X}.app: {}", content_index, rel_path));
                }
            }
        }
    }
    
    // Final Padding to 16-byte boundary
    let padding_needed = (16 - (encryption_buffer.len() % 16)) % 16;
    if padding_needed > 0 {
        let padding = vec![0u8; padding_needed];
        process_chunk(
            &padding, &mut encryption_buffer, &cipher, &mut prev_block,
            &mut app_file, &mut sha256, &mut current_h3_block, &mut h3_hashes
        )?;
    }
    
    // Flush remaining buffer
    if !encryption_buffer.is_empty() {
         encrypt_buffer_inplace(&mut encryption_buffer, &cipher, &mut prev_block);
         app_file.write_all(&encryption_buffer).map_err(|e| e.to_string())?;
         
         // Update H3 with remaining encrypted data
         current_h3_block.extend_from_slice(&encryption_buffer);
         while current_h3_block.len() >= HASH_BLOCK_SIZE {
             let chunk: Vec<u8> = current_h3_block.drain(0..HASH_BLOCK_SIZE).collect();
             let mut hasher = Sha1::new();
             hasher.update(&chunk);
             h3_hashes.extend_from_slice(&hasher.finalize());
         }
    }
    
    // Final H3 hash for partial block
    if !current_h3_block.is_empty() {
        let mut hasher = Sha1::new();
        hasher.update(&current_h3_block);
        h3_hashes.extend_from_slice(&hasher.finalize());
    }
    
    let final_sha256 = sha256.finalize();
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&final_sha256);
    
    let final_size = app_file.metadata().map_err(|e| e.to_string())?.len();
    
    Ok((final_size, hash_arr, h3_hashes))
}

fn collect_files_recursive(dir: &Path, base: &Path, entries: &mut Vec<(String, u64)>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_file() {
            let relative = path.strip_prefix(base).unwrap().to_string_lossy().to_string();
            let size = path.metadata().map_err(|e| e.to_string())?.len();
            entries.push((relative, size));
        } else if path.is_dir() {
            collect_files_recursive(&path, base, entries)?;
        }
    }
    Ok(())
}

fn process_chunk(
    data: &[u8],
    buffer: &mut Vec<u8>,
    cipher: &Aes128,
    prev_block: &mut [u8; 16],
    writer: &mut File,
    sha256: &mut sha2::Sha256,
    h3_buffer: &mut Vec<u8>,
    h3_hashes: &mut Vec<u8>
) -> Result<(), String> {
    sha256.update(data);
    buffer.extend_from_slice(data);
    
    // Encrypt full 16-byte blocks
    while buffer.len() >= 16 {
        // Take 16 bytes, but wait... we might have exactly 16 bytes and this might be the end.
        // Actually, padding is handled at the very end of pack_folder_streaming. 
        // So here we process as many full blocks as possible.
        // Wait, efficient way: find split point
        let split_idx = (buffer.len() / 16) * 16;
        if split_idx == 0 { break; }
        
        let mut chunk: Vec<u8> = buffer.drain(0..split_idx).collect();
        encrypt_buffer_inplace(&mut chunk, cipher, prev_block);
        
        writer.write_all(&chunk).map_err(|e| e.to_string())?;
        
        // H3 processing
        h3_buffer.extend_from_slice(&chunk);
        while h3_buffer.len() >= HASH_BLOCK_SIZE {
             let h3_chunk: Vec<u8> = h3_buffer.drain(0..HASH_BLOCK_SIZE).collect();
             let mut hasher = Sha1::new();
             hasher.update(&h3_chunk);
             h3_hashes.extend_from_slice(&hasher.finalize());
        }
    }
    Ok(())
}

fn encrypt_buffer_inplace(buffer: &mut [u8], cipher: &Aes128, prev_block: &mut [u8; 16]) {
    for chunk in buffer.chunks_mut(16) {
        // XOR with previous
        for i in 0..16 {
            chunk[i] ^= prev_block[i];
        }
        // Encrypt
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        
        chunk.copy_from_slice(&block);
        prev_block.copy_from_slice(&block);
    }
}

/// Parse Title ID from meta/meta.xml
/// Returns the 64-bit Title ID (e.g., 0x0005000010101000)
pub fn parse_title_id_from_meta(meta_dir: &Path) -> Option<u64> {
    let meta_xml_path = meta_dir.join("meta").join("meta.xml");
    
    if !meta_xml_path.exists() {
        println!("   ⚠️ meta.xml not found at: {}", meta_xml_path.display());
        return None;
    }
    
    let content = match fs::read_to_string(&meta_xml_path) {
        Ok(c) => c,
        Err(e) => {
            println!("   ⚠️ Failed to read meta.xml: {}", e);
            return None;
        }
    };
    
    // Look for <title_id type="hexBinary" length="8">XXXXXXXXXXXXXXXX</title_id>
    // or <title_id>XXXXXXXXXXXXXXXX</title_id>
    
    // Simple regex-free parsing
    if let Some(start) = content.find("<title_id") {
        if let Some(rest) = content.get(start..) {
            if let Some(gt) = rest.find('>') {
                if let Some(end) = rest.find("</title_id>") {
                    let id_str = &rest[gt+1..end].trim();
                    // Parse hex string (may have 0x prefix or not)
                    let hex_str = id_str.trim_start_matches("0x").trim_start_matches("0X");
                    match u64::from_str_radix(hex_str, 16) {
                        Ok(id) => {
                            println!("   Found Title ID in meta.xml: {:016X}", id);
                            return Some(id);
                        }
                        Err(_) => {
                            println!("   ⚠️ Failed to parse title_id: {}", id_str);
                        }
                    }
                }
            }
        }
    }
    
    None
}

/// Content file info collected during enumeration
pub struct ContentInfo {
    pub id: u32,
    pub path: std::path::PathBuf,
    pub size: u64,
    pub hash: [u8; 32],
}

pub fn pack_to_wup(
    input_dir: &Path,
    output_dir: &Path,
    common_key: &[u8; 16],
    title_id: u64,
    progress: Option<ProgressCallback>
) -> Result<(), String> {
    println!("📦 Starting WUP packing (Streaming Mode)...");
    
    fs::create_dir_all(output_dir).map_err(|e| format!("Failed to create output dir: {}", e))?;
    
    let title_key = generate_title_key();
    let mut contents: Vec<ContentInfo> = Vec::new();
    let mut content_id = 0u32;
    
    for folder in &["code", "content", "meta"] {
        let folder_path = input_dir.join(folder);
        if folder_path.exists() {
            let app_path = output_dir.join(format!("{:08X}.app", content_id));
            let h3_path = output_dir.join(format!("{:08X}.h3", content_id));
            
            if let Some(cb) = &progress {
                (cb.lock().unwrap())(0.0, &format!("Packing {}...", folder));
            }

            let (size, hash, h3_hashes) = pack_folder_streaming(
                &folder_path, &app_path, &title_key, content_id as u16, progress.as_ref()
            )?;
            
            fs::write(&h3_path, &h3_hashes).map_err(|e| format!("Failed to write .h3: {}", e))?;
            
            contents.push(ContentInfo {
                id: content_id,
                path: app_path,
                size,
                hash,
            });
            content_id += 1;
        }
    }
    
    if contents.is_empty() {
        return Err("No content folders found".to_string());
    }
    
    if let Some(cb) = &progress {
        (cb.lock().unwrap())(1.0, "Generating Metadata...");
    }
    
    generate_tmd(output_dir, title_id, &contents)?;
    generate_ticket(output_dir, title_id, &title_key, common_key)?;
    
    let cert_path = output_dir.join("title.cert");
    fs::write(&cert_path, &[]).map_err(|e| format!("Failed to write cert: {}", e))?;
    
    println!("✅ WUP packing complete!");
    Ok(())
}
/// Generate title.tmd file
fn generate_tmd(output_dir: &Path, title_id: u64, contents: &[ContentInfo]) -> Result<(), String> {
    let mut tmd_data = Vec::new();
    
    // TMD Header
    let mut header = TmdHeader::default();
    header.signature_type = TMD_SIGNATURE_TYPE.to_be();
    header.issuer[..8].copy_from_slice(b"Root-CA\0");
    header.version = 1;
    header.title_id = title_id.to_be();
    header.title_type = 0x00050000u32.to_be(); // Game
    header.num_contents = (contents.len() as u16).to_be();
    header.boot_index = 0;
    
    // Write header
    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            &header as *const TmdHeader as *const u8,
            std::mem::size_of::<TmdHeader>(),
        )
    };
    tmd_data.extend_from_slice(header_bytes);
    
    // Content Info Records (64 entries, most zeroed)
    for _ in 0..64 {
        tmd_data.extend_from_slice(&[0u8; std::mem::size_of::<ContentInfoRecord>()]);
    }
    
    // Content Chunk Records
    for (idx, content) in contents.iter().enumerate() {
        let mut record = ContentChunkRecord::default();
        record.content_id = content.id.to_be();
        record.index = (idx as u16).to_be();
        record.content_type = CONTENT_TYPE_HASHED.to_be();
        record.size = content.size.to_be();
        record.sha256_hash = content.hash;
        
        let record_bytes = unsafe {
            std::slice::from_raw_parts(
                &record as *const ContentChunkRecord as *const u8,
                std::mem::size_of::<ContentChunkRecord>(),
            )
        };
        tmd_data.extend_from_slice(record_bytes);
    }
    
    let tmd_path = output_dir.join("title.tmd");
    fs::write(&tmd_path, &tmd_data).map_err(|e| format!("Failed to write TMD: {}", e))?;
    println!("   Created title.tmd ({} bytes)", tmd_data.len());
    
    Ok(())
}

/// Generate title.tik file
fn generate_ticket(
    output_dir: &Path,
    title_id: u64,
    title_key: &[u8; 16],
    common_key: &[u8; 16],
) -> Result<(), String> {
    let mut ticket = TicketHeader::default();
    
    // Set issuer
    ticket.issuer[..8].copy_from_slice(b"Root-CA\0");
    
    // Encrypt title key with common key
    let encrypted_key = encrypt_title_key(title_key, common_key, title_id);
    ticket.title_key = encrypted_key;
    
    // Set title ID
    ticket.title_id = title_id.to_be();
    
    // Write ticket
    let ticket_bytes = unsafe {
        std::slice::from_raw_parts(
            &ticket as *const TicketHeader as *const u8,
            std::mem::size_of::<TicketHeader>(),
        )
    };
    
    let tik_path = output_dir.join("title.tik");
    fs::write(&tik_path, &ticket_bytes).map_err(|e| format!("Failed to write TIK: {}", e))?;
    println!("   Created title.tik ({} bytes)", ticket_bytes.len());
    
    Ok(())
}
