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

/// Encrypt content data using AES-128-CBC
/// IV is content index as big-endian u16 padded with zeros
pub fn encrypt_content(
    data: &[u8],
    title_key: &[u8; 16],
    content_index: u16,
) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(title_key));
    
    // Pad data to 16-byte boundary
    let padded_len = (data.len() + 15) & !15;
    let mut padded = vec![0u8; padded_len];
    padded[..data.len()].copy_from_slice(data);
    
    // IV = content index (big endian) + 14 zero bytes
    let mut iv = [0u8; 16];
    iv[0..2].copy_from_slice(&content_index.to_be_bytes());
    
    // Encrypt in CBC mode
    let mut result = Vec::with_capacity(padded_len);
    let mut prev_block = iv;
    
    for chunk in padded.chunks(16) {
        // XOR with previous block
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ prev_block[i];
        }
        
        // Encrypt
        let mut encrypted = GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut encrypted);
        
        result.extend_from_slice(&encrypted);
        prev_block.copy_from_slice(&encrypted);
    }
    
    result
}

/// Generate H3 hash file (SHA-1 hash tree)
/// H3 contains hashes of 4MB blocks
pub fn generate_h3_hashes(encrypted_data: &[u8]) -> Vec<u8> {
    let mut hashes = Vec::new();
    
    for chunk in encrypted_data.chunks(HASH_BLOCK_SIZE) {
        let mut hasher = Sha1::new();
        hasher.update(chunk);
        let hash = hasher.finalize();
        hashes.extend_from_slice(&hash);
    }
    
    hashes
}

/// Calculate SHA-256 hash of data
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest as Sha2Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

//=============================================================================
// Packing Functions
//=============================================================================

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

/// Pack code/content/meta folders into WUP installable format
pub fn pack_to_wup(
    input_dir: &Path,
    output_dir: &Path,
    common_key: &[u8; 16],
    title_id: u64,
) -> Result<(), String> {
    println!("📦 Starting WUP packing...");
    println!("   Input:  {}", input_dir.display());
    println!("   Output: {}", output_dir.display());
    println!("   Title ID: {:016X}", title_id);
    
    // Create output directory
    fs::create_dir_all(output_dir).map_err(|e| format!("Failed to create output dir: {}", e))?;
    
    // Generate random title key
    let title_key = generate_title_key();
    println!("   Generated title key: {}", hex::encode(&title_key));
    
    // Enumerate content (we combine code+content+meta into .app files)
    let mut contents: Vec<ContentInfo> = Vec::new();
    let mut content_id = 0u32;
    
    // Process each folder as a content entry
    for folder in &["code", "content", "meta"] {
        let folder_path = input_dir.join(folder);
        if folder_path.exists() {
            // Create a single .app file for each folder
            let app_path = output_dir.join(format!("{:08X}.app", content_id));
            
            // Pack folder contents (simplified: just concatenate files with header)
            let packed_data = pack_folder(&folder_path)?;
            let hash = sha256_hash(&packed_data);
            
            // Encrypt and write
            let encrypted = encrypt_content(&packed_data, &title_key, content_id as u16);
            fs::write(&app_path, &encrypted).map_err(|e| format!("Failed to write .app: {}", e))?;
            
            // Generate H3
            let h3_data = generate_h3_hashes(&encrypted);
            let h3_path = output_dir.join(format!("{:08X}.h3", content_id));
            fs::write(&h3_path, &h3_data).map_err(|e| format!("Failed to write .h3: {}", e))?;
            
            println!("   Created {:08X}.app ({} bytes)", content_id, encrypted.len());
            
            contents.push(ContentInfo {
                id: content_id,
                path: app_path,
                size: packed_data.len() as u64,
                hash,
            });
            
            content_id += 1;
        }
    }
    
    if contents.is_empty() {
        return Err("No content folders found (code/content/meta)".to_string());
    }
    
    // Generate TMD
    generate_tmd(output_dir, title_id, &contents)?;
    
    // Generate Ticket
    generate_ticket(output_dir, title_id, &title_key, common_key)?;
    
    // Generate certificate (empty/placeholder for homebrew)
    let cert_path = output_dir.join("title.cert");
    fs::write(&cert_path, &[]).map_err(|e| format!("Failed to write cert: {}", e))?;
    
    println!("✅ WUP packing complete!");
    Ok(())
}

/// Pack a folder's contents into a byte array
fn pack_folder(folder: &Path) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    
    fn pack_recursive(dir: &Path, base: &Path, data: &mut Vec<u8>) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            
            if path.is_file() {
                let relative = path.strip_prefix(base).unwrap();
                let name = relative.to_string_lossy();
                
                // Write file entry: name length (4 bytes) + name + data length (8 bytes) + data
                let name_bytes = name.as_bytes();
                data.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                data.extend_from_slice(name_bytes);
                
                let mut file_data = fs::read(&path).map_err(|e| e.to_string())?;
                data.extend_from_slice(&(file_data.len() as u64).to_be_bytes());
                data.append(&mut file_data);
            } else if path.is_dir() {
                pack_recursive(&path, base, data)?;
            }
        }
        Ok(())
    }
    
    pack_recursive(folder, folder, &mut data)?;
    Ok(data)
}

/// Generate title.tmd file
fn generate_tmd(output_dir: &Path, title_id: u64, contents: &[ContentInfo]) -> Result<(), String> {
    let mut tmd_data = Vec::new();
    
    // TMD Header
    let mut header = TmdHeader::default();
    header.signature_type = TMD_SIGNATURE_TYPE.to_be();
    header.issuer[..8].copy_from_slice(b"Root-CA");
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
    ticket.issuer[..8].copy_from_slice(b"Root-CA");
    
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
