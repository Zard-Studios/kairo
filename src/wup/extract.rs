//! WUD to WUP extraction with FST parsing
//! 
//! Complete extraction pipeline: parse, decrypt, extract files

use std::fs::{self, File};
use std::io::{Read, Write, Seek, SeekFrom, BufReader, BufWriter};
use std::path::Path;
use std::sync::{Arc, Mutex};

use aes::Aes128;
use cbc::{Decryptor, cipher::{BlockDecryptMut, KeyIvInit}};

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
    
    // Open WUD file
    let mut reader = BufReader::new(File::open(options.wud_path)?);
    
    report_progress(&options.progress, 0.05, "Reading partition table...");
    
    // Read partition table from 0x18000 to find actual GM partition offset
    // Pass common key to decrypt table entries
    let partition_table = crate::wud::PartitionTable::read(&mut reader, options.common_key)?;
    
    // Find GM partition
    let gm_partition = partition_table.game_partition()
        .ok_or_else(|| KairoError::InvalidWud("No GM partition found".into()))?;
    
    let gm_offset = gm_partition.offset;
    let gm_size = gm_partition.size;
    
    report_progress(&options.progress, 0.1, &format!(
        "Found GM partition at offset 0x{:X}, size {} MB", 
        gm_offset, 
        gm_size / 1_000_000
    ));
    
    // Search for FST in the GM partition
    let fst_data = find_and_extract_fst(&mut reader, options.title_key, gm_offset, Some(options.common_key))?;
    
    if fst_data.is_empty() {
        return Err(KairoError::InvalidWud("Could not find FST in disc image".into()));
    }
    
    report_progress(&options.progress, 0.2, "Parsing FST...");
    
    // Parse FST entries
    let (entries, name_table) = parse_fst(&fst_data)?;
    
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
    reader: &mut BufReader<R>,
    key: &[u8; 16],
    partition_offset: u64,
    common_key: Option<&[u8; 16]>, // Add common key for title key decryption
) -> Result<Vec<u8>> {
    const NUM_SECTORS: usize = 4;
    
    // Debug: Read WUD header (first sector) to find Title ID
    let current_pos = reader.stream_position()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut disc_header = [0u8; 0x400];
    reader.read_exact(&mut disc_header)?;
    
    // Print first 64 bytes to identify format
    eprintln!("File Start [0x00..0x40]: {:02X?}", &disc_header[0x00..0x40]);
    // Print Title ID area
    eprintln!("Header dump [0x180..0x1A0]: {:02X?}", &disc_header[0x180..0x1A0]);
    
    // Restore position
    reader.seek(SeekFrom::Start(partition_offset))?;
    
    let mut header_data = vec![0u8; SECTOR_SIZE * NUM_SECTORS];
    reader.read_exact(&mut header_data)?;
    
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
            decrypt_sector(&mut decrypted[start..end], test_key, &iv);
        }
        
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
            decrypt_sector(&mut decrypted_abs[start..end], test_key, &iv);
        }
        
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
        // We need the Title ID to decrypt the key. 
        // Typically at 0x18C, but dump showed zeros.
        // Let's scan the first sector for a Title ID pattern (starts with 00 05 00 ...)
        let mut title_id = [0u8; 8];
        let mut found_tid = false;
        
        // Check 0x18C first
        if disc_header[0x18C] == 0x00 && disc_header[0x18D] == 0x05 {
             title_id.copy_from_slice(&disc_header[0x18C..0x194]);
             found_tid = true;
        } else {
            // Scan
            for i in (0..0x400).step_by(4) {
                if disc_header[i] == 0x00 && disc_header[i+1] == 0x05 && disc_header[i+2] == 0x00 {
                    // Possible Title ID
                    title_id.copy_from_slice(&disc_header[i..i+8]);
                    eprintln!("Found potential Title ID at 0x{:X}: {:02X?}", i, title_id);
                    found_tid = true;
                    break;
                }
            }
        }
        
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
            eprintln!("Could not find Title ID in header - cannot decrypt Title Key properly.");
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
    reader: &mut BufReader<R>,
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
    reader: &mut BufReader<R>,
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
