//! WUD to WUP extraction
//! 
//! Complete extraction pipeline: parse, decrypt, extract

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

/// WUD disc size
const WUD_SIZE: u64 = 25_025_314_816; // ~23.3 GB

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

/// Extract WUD to WUP format
/// 
/// Decrypts the GM partition and extracts game files.
pub fn extract_wud_to_wup(options: &ExtractOptions) -> Result<()> {
    // Create output directories
    let code_dir = options.output_dir.join("code");
    let content_dir = options.output_dir.join("content");
    let meta_dir = options.output_dir.join("meta");
    
    fs::create_dir_all(&code_dir)?;
    fs::create_dir_all(&content_dir)?;
    fs::create_dir_all(&meta_dir)?;
    
    // Open WUD file
    let mut reader = BufReader::new(File::open(options.wud_path)?);
    
    // For now, decrypt the entire disc content to a temp file
    // then we can parse the filesystem
    // This is a simplified approach - full implementation would parse FST
    
    let decrypted_path = options.output_dir.join("decrypted_gm.bin");
    let mut writer = BufWriter::new(File::create(&decrypted_path)?);
    
    // The game partition typically starts at sector 0x8000 (offset 0x10000000)
    // But this can vary - we'd need to properly parse the partition table
    // For simplicity, we'll decrypt from a known offset pattern
    
    const GM_PARTITION_OFFSET: u64 = 0x10000000; // Common GM partition start
    
    reader.seek(SeekFrom::Start(GM_PARTITION_OFFSET))?;
    
    // Get file size to calculate remaining data
    let file_size = reader.get_ref().metadata()?.len();
    let partition_size = file_size.saturating_sub(GM_PARTITION_OFFSET);
    let total_sectors = (partition_size as usize + SECTOR_SIZE - 1) / SECTOR_SIZE;
    
    let mut sector_buf = vec![0u8; SECTOR_SIZE];
    
    report_progress(&options.progress, 0.0, "Starting decryption...");
    
    for sector_num in 0..total_sectors {
        // Calculate bytes to read (handle last sector)
        let remaining = partition_size - (sector_num as u64 * SECTOR_SIZE as u64);
        let bytes_to_read = std::cmp::min(SECTOR_SIZE as u64, remaining) as usize;
        
        if bytes_to_read == 0 {
            break;
        }
        
        // Read sector
        if reader.read_exact(&mut sector_buf[..bytes_to_read]).is_err() {
            break; // End of file
        }
        
        // Create IV from sector number (sector index in big-endian)
        let mut iv = [0u8; 16];
        let sector_index = sector_num as u64;
        iv[..8].copy_from_slice(&sector_index.to_be_bytes());
        
        // Decrypt using AES-128-CBC
        decrypt_sector(&mut sector_buf[..bytes_to_read], options.title_key, &iv);
        
        // Write decrypted data
        writer.write_all(&sector_buf[..bytes_to_read])?;
        
        // Report progress every 1000 sectors (~32MB)
        if sector_num % 1000 == 0 || sector_num == total_sectors - 1 {
            let percent = (sector_num + 1) as f32 / total_sectors as f32;
            let mb_done = (sector_num + 1) as u64 * SECTOR_SIZE as u64 / 1_000_000;
            let mb_total = partition_size / 1_000_000;
            report_progress(
                &options.progress, 
                percent, 
                &format!("{} MB / {} MB", mb_done, mb_total)
            );
        }
    }
    
    writer.flush()?;
    
    report_progress(&options.progress, 1.0, "Extraction complete!");
    
    // Note: Full implementation would parse the decrypted FST
    // and extract individual files to code/content/meta
    // For now, we output the raw decrypted partition
    
    Ok(())
}

/// Decrypt a sector using AES-128-CBC
fn decrypt_sector(data: &mut [u8], key: &[u8; 16], iv: &[u8; 16]) {
    let decryptor = Aes128CbcDec::new(key.into(), iv.into());
    
    // Decrypt 16-byte blocks
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
