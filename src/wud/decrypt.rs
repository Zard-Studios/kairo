//! WUD partition decryption using AES-128-CBC

use crate::error::Result;
use crate::keys::Key;
use aes::Aes128;
use cbc::{Decryptor, cipher::{BlockDecryptMut, KeyIvInit}};
use std::io::{Read, Write, Seek, SeekFrom, BufReader, BufWriter};
use std::fs::File;
use std::path::Path;

type Aes128CbcDec = Decryptor<Aes128>;

/// Block size for AES-128
const BLOCK_SIZE: usize = 16;

/// Sector size for WUD (32 KB)
const SECTOR_SIZE: usize = 0x8000;

/// Progress callback type
pub type ProgressFn = Box<dyn Fn(f32, &str) + Send>;

/// Decrypt a partition from a WUD file
/// 
/// Uses AES-128-CBC with the title key. Each sector uses
/// the sector number as the IV.
pub fn decrypt_partition<P: AsRef<Path>>(
    input: P,
    output: P,
    partition_offset: u64,
    partition_size: u64,
    title_key: &Key,
    on_progress: Option<ProgressFn>,
) -> Result<()> {
    let mut reader = BufReader::new(File::open(input)?);
    let mut writer = BufWriter::new(File::create(output)?);
    
    reader.seek(SeekFrom::Start(partition_offset))?;
    
    let total_sectors = (partition_size as usize + SECTOR_SIZE - 1) / SECTOR_SIZE;
    let mut sector_buf = vec![0u8; SECTOR_SIZE];
    
    for sector_num in 0..total_sectors {
        // Read sector
        let bytes_to_read = std::cmp::min(
            SECTOR_SIZE,
            (partition_size - (sector_num as u64 * SECTOR_SIZE as u64)) as usize
        );
        reader.read_exact(&mut sector_buf[..bytes_to_read])?;
        
        // Create IV from sector number
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&(sector_num as u64).to_be_bytes());
        
        // Decrypt in-place
        let decryptor = Aes128CbcDec::new(title_key.into(), &iv.into());
        
        // Decrypt complete blocks
        let complete_blocks = bytes_to_read / BLOCK_SIZE;
        for block_idx in 0..complete_blocks {
            let start = block_idx * BLOCK_SIZE;
            let end = start + BLOCK_SIZE;
            let block = &mut sector_buf[start..end];
            decryptor.clone().decrypt_block_mut(block.into());
        }
        
        writer.write_all(&sector_buf[..bytes_to_read])?;
        
        // Report progress
        if let Some(ref callback) = on_progress {
            let percent = (sector_num + 1) as f32 / total_sectors as f32;
            callback(percent, &format!("Decrypting sector {}/{}", sector_num + 1, total_sectors));
        }
    }
    
    writer.flush()?;
    Ok(())
}

/// Decrypt a buffer using AES-128-CBC
/// 
/// Helpful for decrypting headers or small structures.
/// IMPORTANT: This properly chains CBC mode - each block uses previous ciphertext as IV
pub fn decrypt_buffer(data: &mut [u8], key: &Key, iv: &[u8; 16]) {
    use cbc::cipher::generic_array::GenericArray;
    
    let mut decryptor = Aes128CbcDec::new(key.into(), iv.into());
    
    let block_count = data.len() / BLOCK_SIZE;
    for i in 0..block_count {
        let start = i * BLOCK_SIZE;
        let end = start + BLOCK_SIZE;
        let block: &mut GenericArray<u8, _> = GenericArray::from_mut_slice(&mut data[start..end]);
        decryptor.decrypt_block_mut(block);
    }
}

/// Decrypt a chunk using JNUSLib-style IV calculation
/// 
/// IV = 16-byte buffer with (file_offset >> 16) at position 0x08
pub fn decrypt_chunk(data: &mut [u8], key: &Key, file_offset: u64) {
    let mut iv = [0u8; 16];
    // WUD sectors are 0x8000 (2^15) bytes
    // IV is the sector index (big endian)
    let iv_value = file_offset >> 15;
    iv[0..8].copy_from_slice(&iv_value.to_be_bytes());
    decrypt_buffer(data, key, &iv);
}
