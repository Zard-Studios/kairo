//! WUD to WUP extraction with FST parsing
//! 
//! Complete extraction pipeline: parse, decrypt, extract files

use std::fs::{self, File};
use std::io::{Read, Write, Seek, SeekFrom, BufReader, BufWriter};
use std::path::Path;
use std::sync::{Arc, Mutex};

use aes::Aes128;
use cbc::{Decryptor, cipher::{BlockDecryptMut, KeyIvInit}};

use crate::wud::{Partition, PartitionType};
use crate::error::{KairoError, Result};

type Aes128CbcDec = Decryptor<Aes128>;

/// Sector size for WUD
const SECTOR_SIZE: usize = 0x8000; // 32 KB

/// FST magic number "FST\0"
const FST_MAGIC: u32 = 0x46535400;

/// Progress callback
pub type ProgressCallback = Arc<Mutex<dyn Fn(f32, &str) + Send>>;

/// Extraction options
pub struct ExtractOptions<'a> {
    pub wud_path: &'a Path,
    pub output_dir: &'a Path,
    pub common_key: &'a [u8; 16],
    pub title_key: &'a [u8; 16],
    pub progress: Option<ProgressCallback>,
}

/// FST Entry (16 bytes each)
#[derive(Debug, Clone)]
struct FstEntry {
    is_dir: bool,
    name_offset: u32,
    offset_or_parent: u32,  // For files: data offset; For dirs: parent dir index
    size_or_next: u32,      // For files: size; For dirs: next sibling index
    flags: u16,
    content_index: u16,
}

impl FstEntry {
    fn from_bytes(data: &[u8]) -> Self {
        let type_and_name = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let is_dir = (type_and_name >> 24) != 0;
        let name_offset = type_and_name & 0x00FFFFFF;
        
        Self {
            is_dir,
            name_offset,
            offset_or_parent: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            size_or_next: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            flags: u16::from_be_bytes([data[12], data[13]]),
            content_index: u16::from_be_bytes([data[14], data[15]]),
        }
    }
}

/// Extract WUD to WUP format
pub fn extract_wud_to_wup(options: &ExtractOptions) -> Result<()> {
    report_progress(&options.progress, 0.0, "Opening WUD file...");
    
    // Validate input file exists and has content
    let metadata = std::fs::metadata(options.wud_path)
        .map_err(|e| KairoError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Cannot access WUD file '{}': {}", options.wud_path.display(), e)
        )))?;
    
    if metadata.len() == 0 {
        return Err(KairoError::InvalidWud(format!(
            "WUD file '{}' is empty (0 bytes)", options.wud_path.display()
        )));
    }
    
    eprintln!("Input file: {} ({:.2} GB)", options.wud_path.display(), metadata.len() as f64 / 1024.0 / 1024.0 / 1024.0);
    
    // Open WUD file
    let mut reader = BufReader::new(File::open(options.wud_path)?);
    
    // Read disc header (first 64 bytes) for product code
    let mut disc_header = [0u8; 64];
    reader.read_exact(&mut disc_header)?;
    
    report_progress(&options.progress, 0.05, "Decrypting partition table...");
    
    // === JNUSLib-style decryption ===
    // WIIU_DECRYPTED_AREA_OFFSET = 0x18000
    const DECRYPTED_AREA_OFFSET: u64 = 0x18000;
    const BLOCK_SIZE: usize = 0x10000; // 64KB blocks for decryption
    const DECRYPTED_AREA_SIGNATURE: [u8; 4] = [0xCC, 0xA6, 0xE6, 0x7B];
    
    // Read one block (64KB) at the decrypted area offset
    reader.seek(SeekFrom::Start(DECRYPTED_AREA_OFFSET))?;
    let mut partition_toc_block = vec![0u8; BLOCK_SIZE];
    reader.read_exact(&mut partition_toc_block)?;
    
    // Decrypt using disc key (title_key) with JNUSLib IV calculation
    // IV = (file_offset >> 16) at position 0x08
    crate::wud::decrypt::decrypt_chunk(&mut partition_toc_block, options.title_key, DECRYPTED_AREA_OFFSET);
    
    eprintln!("Decrypted TOC signature: {:02X?}", &partition_toc_block[0..4]);
    
    // Verify signature
    if partition_toc_block[0..4] != DECRYPTED_AREA_SIGNATURE {
        eprintln!("⚠️ TOC signature mismatch! Expected {:02X?}, got {:02X?}", 
                  DECRYPTED_AREA_SIGNATURE, &partition_toc_block[0..4]);
        
        // Try with database key if available
        if let Some(product_code) = crate::disc_keys::extract_product_code(&disc_header) {
            if let Some(key_hex) = crate::disc_keys::lookup_disc_key(&product_code) {
                if let Some(db_key) = crate::disc_keys::parse_hex_key(key_hex) {
                    eprintln!("🔑 Trying database key for {}", product_code);
                    
                    // Re-read and try with database key
                    reader.seek(SeekFrom::Start(DECRYPTED_AREA_OFFSET))?;
                    reader.read_exact(&mut partition_toc_block)?;
                    crate::wud::decrypt::decrypt_chunk(&mut partition_toc_block, &db_key, DECRYPTED_AREA_OFFSET);
                    
                    eprintln!("Database key decrypted TOC signature: {:02X?}", &partition_toc_block[0..4]);
                    
                    if partition_toc_block[0..4] != DECRYPTED_AREA_SIGNATURE {
                        return Err(KairoError::InvalidWud(
                            "Failed to decrypt partition table - wrong disc key?".to_string()
                        ));
                    }
                    eprintln!("✅ Database key worked!");
                }
            }
        } else {
            return Err(KairoError::InvalidWud(
                "Failed to decrypt partition table - wrong disc key?".to_string()
            ));
        }
    } else {
        eprintln!("✅ TOC signature verified!");
    }
    
    // Parse partition count from TOC (offset 0x1C, big-endian u32)
    let partition_count = u32::from_be_bytes([
        partition_toc_block[0x1C], partition_toc_block[0x1D],
        partition_toc_block[0x1E], partition_toc_block[0x1F]
    ]) as usize;
    
    eprintln!("Found {} partitions in TOC", partition_count);
    
    // Parse partition entries from TOC (starting at offset 0x800)
    const PARTITION_TOC_OFFSET: usize = 0x800;
    const PARTITION_TOC_ENTRY_SIZE: usize = 0x80;
    
    let mut gm_partition_offset: Option<u64> = None;
    
    for i in 0..partition_count {
        let entry_offset = PARTITION_TOC_OFFSET + (i * PARTITION_TOC_ENTRY_SIZE);
        if entry_offset + PARTITION_TOC_ENTRY_SIZE > partition_toc_block.len() {
            break;
        }
        
        // Read partition name (null-terminated string at start of entry)
        let name_bytes = &partition_toc_block[entry_offset..entry_offset + 0x19];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();
        
        // Read partition offset (at entry + 0x20, as sector count)
        let offset_in_sectors = u32::from_be_bytes([
            partition_toc_block[entry_offset + 0x20],
            partition_toc_block[entry_offset + 0x21],
            partition_toc_block[entry_offset + 0x22],
            partition_toc_block[entry_offset + 0x23],
        ]) as u64;
        
        let partition_offset_abs = offset_in_sectors * SECTOR_SIZE as u64;
        
        eprintln!("  Partition {}: '{}' at offset 0x{:X}", i, name, partition_offset_abs);
        
        // Look for GM partition (game content)
        if name.starts_with("GM") && gm_partition_offset.is_none() {
            gm_partition_offset = Some(partition_offset_abs);
        }
    }
    
    let gm_offset = gm_partition_offset.ok_or_else(|| 
        KairoError::InvalidWud("No GM partition found in TOC".to_string())
    )?;
    
    eprintln!("🎮 Using GM partition at offset 0x{:X}", gm_offset);
    
    // Now read FST from GM partition
    // The partition starts with a header, followed by the FST
    report_progress(&options.progress, 0.1, "Reading FST from GM partition...");
    
    // Read partition header (first 0x20 bytes)
    const PARTITION_START_SIGNATURE: [u8; 4] = [0xCC, 0x93, 0xA4, 0xF5];
    
    reader.seek(SeekFrom::Start(gm_offset))?;
    let mut partition_header_raw = vec![0u8; 0x20];
    reader.read_exact(&mut partition_header_raw)?;
    
    // Decrypt partition header
    crate::wud::decrypt::decrypt_chunk(&mut partition_header_raw, options.title_key, gm_offset);
    
    eprintln!("Partition header signature: {:02X?}", &partition_header_raw[0..4]);
    
    if partition_header_raw[0..4] != PARTITION_START_SIGNATURE {
        return Err(KairoError::InvalidWud(
            format!("Invalid partition header signature at 0x{:X}", gm_offset)
        ));
    }
    
    eprintln!("✅ Partition header verified!");
    
    // Read header size (offset 0x04)
    let header_size = u32::from_be_bytes([
        partition_header_raw[0x04], partition_header_raw[0x05],
        partition_header_raw[0x06], partition_header_raw[0x07]
    ]) as u64;
    
    // Read FST size (offset 0x14)
    let fst_size = u32::from_be_bytes([
        partition_header_raw[0x14], partition_header_raw[0x15],
        partition_header_raw[0x16], partition_header_raw[0x17]
    ]) as u64;
    
    eprintln!("Partition header size: 0x{:X}", header_size);
    eprintln!("FST size: 0x{:X} ({} KB)", fst_size, fst_size / 1024);
    
    // FST is located at partition_offset + header_size
    let fst_offset = gm_offset + header_size;
    
    reader.seek(SeekFrom::Start(fst_offset))?;
    let mut fst_content = vec![0u8; fst_size as usize];
    reader.read_exact(&mut fst_content)?;
    
    // Decrypt FST
    crate::wud::decrypt::decrypt_chunk(&mut fst_content, options.title_key, fst_offset);
    
    // Verify FST magic ("FST\0")
    const FST_SIGNATURE: [u8; 4] = [0x46, 0x53, 0x54, 0x00];
    eprintln!("FST header: {:02X?}", &fst_content[0..4]);
    
    if fst_content[0..4] != FST_SIGNATURE {
        return Err(KairoError::InvalidWud(
            "Invalid FST signature - decryption failed?".to_string()
        ));
    }
    
    
    eprintln!("✅ FST decrypted and verified! Size: {} bytes", fst_content.len());
    
    report_progress(&options.progress, 0.15, &format!(
        "GM partition at offset 0x{:X}, FST parsed", 
        gm_offset
    ));
    
    report_progress(&options.progress, 0.2, "Parsing FST...");
    
    // Parse FST entries
    let (entries, name_table) = parse_fst(&fst_content)?;
    
    report_progress(&options.progress, 0.25, &format!("Found {} entries, extracting...", entries.len()));
    
    // Extract files
    let total_files = entries.iter().filter(|e| !e.is_dir).count();
    let mut extracted = 0;
    
    // Build directory tree and extract files
    extract_entries(
        &mut reader,
        options,
        &entries,
        &name_table,
        gm_offset,
        0,
        options.output_dir,
        &mut extracted,
        total_files,
    )?;
    
    report_progress(&options.progress, 1.0, &format!("Done! Extracted {} files", extracted));
    
    Ok(())
}

/// Find FST by reading partition header
fn find_and_extract_fst<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    key: &[u8; 16],
    common_key: Option<&[u8; 16]>,
    disc_header: &[u8]
) -> Result<Vec<u8>> {
    eprintln!("Searching for FST in partition at 0x{:X}...", partition_offset);
    
    // Read the first few sectors of the partition
    // The FST is usually at the start of the partition's data area (boot.bin, etc.)
    // But it's encrypted.
    
    // The boot.bin / FST header is in the first encrypted block (cluster 0, sector 0?)
    // Actually, usually headers are at start of partition.
    
    // Read enough data to cover potential FST header
    const NUM_SECTORS: usize = 2; // Read 2 sectors (64KB)
    
    // Validate offset against file size?
    let file_len = reader.seek(SeekFrom::End(0))?;
    if partition_offset >= file_len {
         eprintln!("  Skipping partition: offset 0x{:X} >= file length 0x{:X}", partition_offset, file_len);
         return Ok(Vec::new());
    }
    
    reader.seek(SeekFrom::Start(partition_offset))?;
    
    let mut header_data = vec![0u8; SECTOR_SIZE * NUM_SECTORS];
    if let Err(e) = reader.read_exact(&mut header_data) {
        eprintln!("  Failed to read partition header: {}", e);
        return Ok(Vec::new());
    }
    
    // Helper to try a key
    let try_key = |test_key: &[u8; 16], key_name: &str| -> Option<Vec<u8>> {
        eprintln!("Trying {} Key: {:02X?}", key_name, test_key);
        
        // Try Relative IVs
        let mut decrypted = header_data.clone();
        for sector_idx in 0..NUM_SECTORS {
            let start = sector_idx * SECTOR_SIZE;
            let end = start + SECTOR_SIZE;
            let mut iv = [0u8; 16];
            iv[..8].copy_from_slice(&(sector_idx as u64).to_be_bytes());
            crate::wud::decrypt::decrypt_buffer(&mut decrypted[start..end], test_key, &iv);
        }
        
        eprintln!("  [{}] Relative IV Decrypt (First 16 bytes): {:02X?}", key_name, &decrypted[0..16]);
        
        if let Some(fst) = check_fst(&decrypted) {
            eprintln!("Found FST using {} Key + Relative IVs", key_name);
            return Some(fst);
        }
        
        // Try Absolute IVs
        let abs_sector_start = partition_offset / SECTOR_SIZE as u64;
        let mut decrypted_abs = header_data.clone();
        for sector_idx in 0..NUM_SECTORS {
            let start = sector_idx * SECTOR_SIZE;
            let end = start + SECTOR_SIZE;
            let mut iv = [0u8; 16];
            iv[..8].copy_from_slice(&(abs_sector_start + sector_idx as u64).to_be_bytes());
            crate::wud::decrypt::decrypt_buffer(&mut decrypted_abs[start..end], test_key, &iv);
        }
        
        eprintln!("  [{}] Absolute IV Decrypt (First 16 bytes): {:02X?}", key_name, &decrypted_abs[0..16]);
        
        if let Some(fst) = check_fst(&decrypted_abs) {
            eprintln!("Found FST using {} Key + Absolute IVs", key_name);
            return Some(fst);
        }
        
        None
    };
    
    // 1. Try provided key directly
    if let Some(fst) = try_key(key, "Provided") {
        return Ok(fst);
    }
    
    // 2. Try decrypting the provided key (assuming it's an Encrypted Title Key)
    if let Some(comm_key) = common_key {
        let mut title_id = [0u8; 8];
        let mut found_tid = false;
        
        // Strategy A: Scan for Ticket/TitleID in first 64KB
        let mut large_header = vec![0u8; 0x10000]; // 64KB
        reader.seek(SeekFrom::Start(0))?;
        if reader.read_exact(&mut large_header).is_ok() {
             for i in (0..large_header.len()-8).step_by(4) {
                // Title IDs usually start with 00 05 00 ...
                if large_header[i] == 0x00 && large_header[i+1] == 0x05 && large_header[i+2] == 0x00 {
                    title_id.copy_from_slice(&large_header[i..i+8]);
                    eprintln!("Found potential Title ID at 0x{:X}: {:02X?}", i, title_id);
                    found_tid = true;
                    break;
                }
            }
        }
        
        // Strategy B: Fallback using Game ID (Product Code)
        if !found_tid {
             let game_id_str = String::from_utf8_lossy(&large_header[0..10]);
             eprintln!("Game ID from header: {}", game_id_str);
             
             // Known Game ID map (expand as needed or fetch online?)
             if game_id_str.contains("ANXP") { // Wii Party U (EUR)
                 eprintln!("Detected Wii Party U (EUR) - Using known Title ID");
                 title_id = [0x00, 0x05, 0x00, 0x00, 0x10, 0x14, 0x5C, 0x00];
                 found_tid = true;
             }
        }
        
        reader.seek(SeekFrom::Start(partition_offset))?;
        
        if found_tid {
            let mut decrypted_title_key = *key;
            let mut iv = [0u8; 16];
            iv[..8].copy_from_slice(&title_id);
            // iv[8..] is 0
            
            eprintln!("Decrypting Title Key using Common Key and IV (TitleID): {:02X?}", iv);
            crate::wud::decrypt::decrypt_buffer(&mut decrypted_title_key, comm_key, &iv);
            
            eprintln!("Decrypted Title Key candidate: {:02X?}", decrypted_title_key);
            
            if let Some(fst) = try_key(&decrypted_title_key, "Decrypted") {
                return Ok(fst);
            }
        } else {
            eprintln!("Could not find Title ID - cannot decrypt Title Key properly.");
        }
    }
    
    // 3. Try known disc key from our database!
    // Read product code from header
    if disc_header.len() >= 10 {
        let header_str = String::from_utf8_lossy(&disc_header[0..10]);
        
        // Extract 4-char product code (e.g., "ANXP" from "WUP-P-ANXP")
        if header_str.starts_with("WUP-P-") && disc_header.len() >= 10 {
            let product_code = String::from_utf8_lossy(&disc_header[6..10]).to_string();
            
            if let Some(known_key_hex) = crate::disc_keys::lookup_disc_key(&product_code) {
                if let Some(known_key) = crate::disc_keys::parse_hex_key(known_key_hex) {
                    let game_name = crate::disc_keys::get_game_name(&product_code).unwrap_or("Unknown");
                    let region = crate::disc_keys::get_region(&product_code);
                    
                    eprintln!("🔑 Trying known disc key for {} [{}]", game_name, region);
                    eprintln!("   Key: {}", known_key_hex);
                    
                    if let Some(fst) = try_key(&known_key, "Database") {
                        eprintln!("✅ Found FST using database key!");
                        return Ok(fst);
                    }
                }
            }
        }
    }
    
    Ok(Vec::new())
}

fn check_fst(data: &[u8]) -> Option<Vec<u8>> {
    // Search for FST magic
    for i in 0..(data.len() - 32) {
        let magic = u32::from_be_bytes([
            data[i], data[i+1], data[i+2], data[i+3]
        ]);
        
        if magic == FST_MAGIC {
            // Check potential size
             if i + 32 <= data.len() {
                let entry_count = u32::from_be_bytes([
                    data[i+8], data[i+9], data[i+10], data[i+11]
                ]) as usize;
                
                if entry_count > 0 && entry_count < 100_000 {
                    let fst_size = 0x20 + entry_count * 0x10 + 0x10000;
                    let fst_start = i;
                    let fst_end = std::cmp::min(fst_start + fst_size, data.len());
                    return Some(data[fst_start..fst_end].to_vec());
                }
            }
        }
    }
    None
}



/// Parse FST data into entries and name table
fn parse_fst(data: &[u8]) -> Result<(Vec<FstEntry>, Vec<u8>)> {
    if data.len() < 0x20 {
        return Err(KairoError::InvalidWud("FST too small".into()));
    }
    
    // FST header
    let _magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let entry_count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
    
    if entry_count == 0 || entry_count > 1_000_000 {
        return Err(KairoError::InvalidWud("Invalid FST entry count".into()));
    }
    
    let entries_start = 0x20;
    let entries_size = entry_count * 0x10;
    let name_table_start = entries_start + entries_size;
    
    if name_table_start > data.len() {
        return Err(KairoError::InvalidWud("FST data truncated".into()));
    }
    
    let mut entries = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let offset = entries_start + i * 0x10;
        if offset + 0x10 <= data.len() {
            entries.push(FstEntry::from_bytes(&data[offset..offset + 0x10]));
        }
    }
    
    let name_table = data[name_table_start..].to_vec();
    
    Ok((entries, name_table))
}

/// Get name from name table
fn get_name(name_table: &[u8], offset: u32) -> String {
    let start = offset as usize;
    if start >= name_table.len() {
        return String::new();
    }
    
    let end = name_table[start..].iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(name_table.len());
    
    String::from_utf8_lossy(&name_table[start..end]).to_string()
}

/// Extract all entries recursively  
fn extract_entries<R: Read + Seek>(
    reader: &mut R,
    options: &ExtractOptions,
    entries: &[FstEntry],
    name_table: &[u8],
    partition_offset: u64,
    entry_idx: usize,
    current_dir: &Path,
    extracted: &mut usize,
    total: usize,
) -> Result<()> {
    if entry_idx >= entries.len() {
        return Ok(());
    }
    
    let entry = &entries[entry_idx];
    let name = get_name(name_table, entry.name_offset);
    
    if name.is_empty() || name == "." {
        // Skip root or empty entries, continue with next
        if entry_idx + 1 < entries.len() {
            return extract_entries(reader, options, entries, name_table, 
                partition_offset, entry_idx + 1, current_dir, extracted, total);
        }
        return Ok(());
    }
    
    let path = current_dir.join(&name);
    
    if entry.is_dir {
        // Create directory
        fs::create_dir_all(&path)?;
        
        // Process children (entries until next sibling)
        let next_idx = entry.size_or_next as usize;
        let mut child_idx = entry_idx + 1;
        while child_idx < next_idx && child_idx < entries.len() {
            extract_entries(reader, options, entries, name_table,
                partition_offset, child_idx, &path, extracted, total)?;
            
            // Skip to next sibling
            if entries[child_idx].is_dir {
                child_idx = entries[child_idx].size_or_next as usize;
            } else {
                child_idx += 1;
            }
        }
    } else {
        // Extract file
        let file_offset = (entry.offset_or_parent as u64) * 0x20; // Multiply by offset factor
        let file_size = entry.size_or_next as u64;
        
        extract_file(reader, options, partition_offset + file_offset, file_size, &path)?;
        
        *extracted += 1;
        let percent = 0.25 + (*extracted as f32 / total as f32) * 0.75;
        report_progress(&options.progress, percent, &format!("Extracting: {}", name));
    }
    
    Ok(())
}

/// Extract a single file
fn extract_file<R: Read + Seek>(
    reader: &mut R,
    options: &ExtractOptions,
    offset: u64,
    size: u64,
    output_path: &Path,
) -> Result<()> {
    // Create parent directories
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    let mut writer = BufWriter::new(File::create(output_path)?);
    reader.seek(SeekFrom::Start(offset))?;
    
    let mut remaining = size;
    let mut sector_idx = offset / SECTOR_SIZE as u64;
    let mut sector_buf = vec![0u8; SECTOR_SIZE];
    
    // Handle partial first sector
    let offset_in_sector = (offset % SECTOR_SIZE as u64) as usize;
    
    while remaining > 0 {
        let bytes_to_read = std::cmp::min(SECTOR_SIZE as u64, remaining + offset_in_sector as u64) as usize;
        
        if reader.read_exact(&mut sector_buf[..bytes_to_read]).is_err() {
            break;
        }
        
        // Decrypt sector
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&sector_idx.to_be_bytes());
        decrypt_sector(&mut sector_buf[..bytes_to_read], options.title_key, &iv);
        
        // Write the relevant portion
        let start = if sector_idx == offset / SECTOR_SIZE as u64 { offset_in_sector } else { 0 };
        let end = std::cmp::min(bytes_to_read, start + remaining as usize);
        let write_size = end - start;
        
        writer.write_all(&sector_buf[start..end])?;
        remaining -= write_size as u64;
        sector_idx += 1;
    }
    
    writer.flush()?;
    Ok(())
}

/// Decrypt a sector using AES-128-CBC
fn decrypt_sector(data: &mut [u8], key: &[u8; 16], iv: &[u8; 16]) {
    let decryptor = Aes128CbcDec::new(key.into(), iv.into());
    
    let block_count = data.len() / 16;
    for i in 0..block_count {
        let start = i * 16;
        let end = start + 16;
        let block = &mut data[start..end];
        decryptor.clone().decrypt_block_mut(block.into());
    }
}

/// Helper to report progress
fn report_progress(callback: &Option<ProgressCallback>, percent: f32, message: &str) {
    if let Some(cb) = callback {
        if let Ok(f) = cb.lock() {
            f(percent, message);
        }
    }
}
