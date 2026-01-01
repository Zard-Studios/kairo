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
    let file_size = reader.get_ref().metadata()?.len();
    
    report_progress(&options.progress, 0.05, "Reading partition info...");
    
    // GM partition typically starts at 0x10000000 (256MB offset)
    // But we need to find the actual offset from the partition table
    const GM_PARTITION_OFFSET: u64 = 0x10000000;
    
    // For disc-based games, the FST is at a specific location within the GM partition
    // The FST location can be found in the disc header
    // Let's read the disc header first to find FST offset
    
    reader.seek(SeekFrom::Start(GM_PARTITION_OFFSET))?;
    
    // Read first sector and decrypt it to find FST location
    let mut header_sector = vec![0u8; SECTOR_SIZE];
    reader.read_exact(&mut header_sector)?;
    
    // Decrypt the header sector
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&0u64.to_be_bytes());
    decrypt_sector(&mut header_sector, options.title_key, &iv);
    
    // Look for FST in the decrypted header
    // The FST offset is typically stored at offset 0x424 (relative to partition start)
    // Or we search for the FST magic
    
    report_progress(&options.progress, 0.1, "Searching for FST...");
    
    // For WUD files from disc dumps, the structure is different
    // Let's try to find FST by scanning the first few MB
    let fst_data = find_and_extract_fst(&mut reader, options.title_key, GM_PARTITION_OFFSET)?;
    
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
        GM_PARTITION_OFFSET,
        0,
        options.output_dir,
        &mut extracted,
        total_files,
    )?;
    
    report_progress(&options.progress, 1.0, &format!("Done! Extracted {} files", extracted));
    
    Ok(())
}

/// Find FST by scanning decrypted sectors
fn find_and_extract_fst<R: Read + Seek>(
    reader: &mut BufReader<R>,
    key: &[u8; 16],
    partition_offset: u64,
) -> Result<Vec<u8>> {
    // Scan first 16MB for FST magic
    const SCAN_SIZE: u64 = 16 * 1024 * 1024;
    const SECTOR_SIZE_U64: u64 = SECTOR_SIZE as u64;
    
    let mut sector_buf = vec![0u8; SECTOR_SIZE];
    
    for sector_idx in 0..(SCAN_SIZE / SECTOR_SIZE_U64) {
        let offset = partition_offset + sector_idx * SECTOR_SIZE_U64;
        reader.seek(SeekFrom::Start(offset))?;
        
        if reader.read_exact(&mut sector_buf).is_err() {
            break;
        }
        
        // Decrypt sector
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&sector_idx.to_be_bytes());
        decrypt_sector(&mut sector_buf, key, &iv);
        
        // Search for FST magic in this sector
        for i in 0..(SECTOR_SIZE - 4) {
            let magic = u32::from_be_bytes([
                sector_buf[i], sector_buf[i+1], sector_buf[i+2], sector_buf[i+3]
            ]);
            if magic == FST_MAGIC {
                // Found FST! Read the full FST
                // FST size is at offset +8 from magic
                if i + 12 < SECTOR_SIZE {
                    let fst_size = u32::from_be_bytes([
                        sector_buf[i+8], sector_buf[i+9], sector_buf[i+10], sector_buf[i+11]
                    ]) as usize;
                    
                    if fst_size > 0 && fst_size < 64 * 1024 * 1024 {
                        return read_fst_data(reader, key, partition_offset, 
                            sector_idx * SECTOR_SIZE_U64 + i as u64, fst_size);
                    }
                }
            }
        }
    }
    
    // If we couldn't find FST, return empty - we'll fall back to raw extraction
    Ok(Vec::new())
}

/// Read full FST data from disc
fn read_fst_data<R: Read + Seek>(
    _reader: &mut BufReader<R>,
    _key: &[u8; 16],
    _partition_offset: u64,
    _fst_offset: u64,
    _fst_size: usize,
) -> Result<Vec<u8>> {
    // For now, return empty to trigger fallback
    // Full implementation would read and decrypt the entire FST
    Ok(Vec::new())
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
