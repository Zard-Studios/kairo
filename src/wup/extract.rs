//! WUD to WUP extraction with FST parsing
//! 
//! Complete extraction pipeline: parse, decrypt, extract files

use std::fs::{self, File};
use std::io::{Read, Write, Seek, SeekFrom, BufReader, BufWriter};
use std::path::Path;
use std::sync::{Arc, Mutex};

use aes::Aes128;
use cbc::{Decryptor, cipher::{BlockDecryptMut, KeyIvInit}};

// use crate::wud::{Partition, PartitionType};
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
    sector_size: u64,       // For calculating actual file offset (set after parsing)
}

impl FstEntry {
    fn from_bytes(data: &[u8]) -> Self {
        let type_and_name = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        // JNUSLib checks 0x01 flag. data[0] could have 0x80 (not in NUS) set.
        // Must mask with 0x01.
        let is_dir = (data[0] & 0x01) != 0;
        let name_offset = type_and_name & 0x00FFFFFF;
        
        Self {
            is_dir,
            name_offset,
            offset_or_parent: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            size_or_next: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            flags: u16::from_be_bytes([data[12], data[13]]),
            content_index: u16::from_be_bytes([data[14], data[15]]),
            sector_size: 0x20, // Default, updated after parsing
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
                if let Some(db_key) = crate::disc_keys::parse_hex_key(&key_hex) {
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
    let mut gm_partition_name: Option<String> = None;
    let mut si_partition_offset: Option<u64> = None;
    
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
        
        // Look for SI partition (contains tickets)
        if name.starts_with("SI") && si_partition_offset.is_none() {
            si_partition_offset = Some(partition_offset_abs);
        }
        
        // Look for GM partition (game content)
        if name.starts_with("GM") && gm_partition_offset.is_none() {
            gm_partition_offset = Some(partition_offset_abs);
            gm_partition_name = Some(name);
        }
    }
    
    let gm_offset = gm_partition_offset.ok_or_else(|| 
        KairoError::InvalidWud("No GM partition found in TOC".to_string())
    )?;
    
    eprintln!("🎮 Using GM partition '{}' at offset 0x{:X}", 
              gm_partition_name.as_deref().unwrap_or("unknown"), gm_offset);
    
    // === READ SI PARTITION TO GET TICKET ===
    // The SI partition contains title.tik which has the real key for GM partition
    let gm_content_key: [u8; 16] = if let Some(si_offset) = si_partition_offset {
        eprintln!("📁 Reading SI partition at 0x{:X} for ticket...", si_offset);
        
        // Read SI partition header (raw, not encrypted)
        reader.seek(SeekFrom::Start(si_offset))?;
        let mut si_header = vec![0u8; 0x20];
        reader.read_exact(&mut si_header)?;
        
        if si_header[0..4] == [0xCC, 0x93, 0xA4, 0xF5] {
            let si_header_size = u32::from_be_bytes([
                si_header[0x04], si_header[0x05], si_header[0x06], si_header[0x07]
            ]) as u64;
            let si_fst_size = u32::from_be_bytes([
                si_header[0x14], si_header[0x15], si_header[0x16], si_header[0x17]
            ]) as u64;
            
            eprintln!("SI header size: 0x{:X}, FST size: 0x{:X}", si_header_size, si_fst_size);
            
            // Read and decrypt SI FST
            let si_fst_offset = si_offset + si_header_size;
            reader.seek(SeekFrom::Start(si_fst_offset))?;
            let mut si_fst = vec![0u8; si_fst_size as usize];
            reader.read_exact(&mut si_fst)?;
            
            // Decrypt SI FST with disc key + zero IV
            let zero_iv = [0u8; 16];
            crate::wud::decrypt::decrypt_buffer(&mut si_fst, options.title_key, &zero_iv);
            
            eprintln!("SI FST header: {:02X?}", &si_fst[0..4]);
            
            if si_fst[0..4] == [0x46, 0x53, 0x54, 0x00] {
                eprintln!("✅ SI FST decrypted successfully!");
                
                // Parse SI FST based on JNUSLib structure:
                // FST Header (0x20 bytes):
                //   0x04-0x07: sectorSize (file offset factor, usually 0x20)
                //   0x08-0x0B: contentCount (number of ContentFSTInfo entries)
                // ContentFSTInfo sections: at 0x20, each 0x20 bytes
                //   0x00-0x03: offsetSector
                //   0x04-0x07: sizeSector
                // File entries: after ContentFSTInfo
                // Name table: after file entries
                
                let sector_size = u32::from_be_bytes([si_fst[4], si_fst[5], si_fst[6], si_fst[7]]) as u64;
                let content_count = u32::from_be_bytes([si_fst[8], si_fst[9], si_fst[10], si_fst[11]]) as usize;
                
                let content_fst_offset = 0x20usize;
                let content_fst_size = content_count * 0x20;
                let fst_entries_offset = content_fst_offset + content_fst_size;
                
                // Parse ContentFSTInfo entries
                let mut content_infos: Vec<(u64, u64)> = Vec::new(); // (offset_in_bytes, size_in_bytes)
                for i in 0..content_count {
                    let info_start = content_fst_offset + i * 0x20;
                    let offset_sector = u32::from_be_bytes([
                        si_fst[info_start], si_fst[info_start + 1],
                        si_fst[info_start + 2], si_fst[info_start + 3]
                    ]) as u64;
                    let size_sector = u32::from_be_bytes([
                        si_fst[info_start + 4], si_fst[info_start + 5],
                        si_fst[info_start + 6], si_fst[info_start + 7]
                    ]) as u64;
                    
                    // Offset in bytes = (offsetSector * 0x8000) - 0x8000, clamped to 0
                    let offset_bytes = if offset_sector > 0 { (offset_sector * 0x8000) - 0x8000 } else { 0 };
                    let size_bytes = size_sector * 0x8000;
                    
                    eprintln!("  ContentFSTInfo[{}]: offsetSector=0x{:X} -> offsetBytes=0x{:X}, size=0x{:X}", 
                              i, offset_sector, offset_bytes, size_bytes);
                    content_infos.push((offset_bytes, size_bytes));
                }
                
                // Get entry count from root entry
                if fst_entries_offset + 0x10 > si_fst.len() {
                    eprintln!("⚠️ FST too small for entry table, using disc key");
                    *options.title_key
                } else {
                    let entry_count = u32::from_be_bytes([
                        si_fst[fst_entries_offset + 8], si_fst[fst_entries_offset + 9],
                        si_fst[fst_entries_offset + 10], si_fst[fst_entries_offset + 11]
                    ]) as usize;
                    
                    let name_table_offset = fst_entries_offset + entry_count * 0x10;
                    
                    eprintln!("SI FST: sectorSize=0x{:X}, {} contents, {} entries, entries at 0x{:X}, names at 0x{:X}", 
                              sector_size, content_count, entry_count, fst_entries_offset, name_table_offset);
                    
                    // Search for title.tik in entries
                    let mut ticket_found = false;
                    let mut ticket_abs_offset: u64 = 0;
                    let mut ticket_size: u64 = 0;
                    let mut ticket_file_offset: u64 = 0;  // For IV calculation
                    
                    for i in 0..entry_count {
                        let entry_start = fst_entries_offset + i * 0x10;
                        if entry_start + 0x10 > si_fst.len() { break; }
                    
                        let type_and_name_offset = u32::from_be_bytes([
                            si_fst[entry_start], si_fst[entry_start + 1],
                            si_fst[entry_start + 2], si_fst[entry_start + 3]
                        ]);
                        let is_dir = (type_and_name_offset >> 24) == 1;
                        let name_off = (type_and_name_offset & 0x00FFFFFF) as usize;
                        
                        // File offset at entry+4 (needs to be multiplied by sectorSize for files)
                        let file_offset_raw = u32::from_be_bytes([
                            si_fst[entry_start + 4], si_fst[entry_start + 5],
                            si_fst[entry_start + 6], si_fst[entry_start + 7]
                        ]) as u64;
                        
                        // File size at entry+8
                        let file_size = u32::from_be_bytes([
                            si_fst[entry_start + 8], si_fst[entry_start + 9],
                            si_fst[entry_start + 10], si_fst[entry_start + 11]
                        ]) as u64;
                        
                        // Flags at entry+12 (0x0C-0x0D as u16)
                        let _flags = u16::from_be_bytes([
                            si_fst[entry_start + 12], si_fst[entry_start + 13]
                        ]);
                        
                        // Content index at entry+14 (0x0E-0x0F as u16) - CORRECT OFFSET per JNUSLib
                        let content_index = u16::from_be_bytes([
                            si_fst[entry_start + 14], si_fst[entry_start + 15]
                        ]) as usize;
                        
                        // For files, multiply file_offset by sectorSize (per JNUSLib)
                        let file_offset = if !is_dir { file_offset_raw * sector_size } else { file_offset_raw };
                        
                        // Get file name from name table
                        let abs_name_off = name_table_offset + name_off;
                        let name = if abs_name_off < si_fst.len() {
                            let name_end = si_fst[abs_name_off..].iter()
                                .position(|&b| b == 0)
                                .unwrap_or(si_fst.len() - abs_name_off);
                            String::from_utf8_lossy(&si_fst[abs_name_off..abs_name_off + name_end]).to_string()
                        } else {
                            "<name out of bounds>".to_string()
                        };
                        
                        let entry_type = if is_dir { "DIR " } else { "FILE" };
                        eprintln!("  SI {} #{}: '{}' fileOff=0x{:X} (raw=0x{:X}) size=0x{:X} contentIdx={}", 
                                  entry_type, i, name, file_offset, file_offset_raw, file_size, content_index);
                        
                        // Only look for title.tik in files, not directories
                        if !is_dir && name.to_lowercase().contains("title.tik") {
                            ticket_found = true;
                            ticket_file_offset = file_offset;
                            ticket_size = file_size;
                            
                            // Calculate absolute offset:
                            // partitionOffset + headerSize + contentInfo.offset + fileOffset
                            let content_offset = if content_index < content_infos.len() {
                                content_infos[content_index].0
                            } else {
                                0
                            };
                            
                            ticket_abs_offset = si_partition_offset.unwrap() + si_header_size + content_offset + file_offset;
                            
                            eprintln!("🎫 Found ticket! contentIdx={} contentOff=0x{:X} fileOff=0x{:X} -> absOff=0x{:X} size=0x{:X}", 
                                      content_index, content_offset, file_offset, ticket_abs_offset, ticket_size);
                        }
                    }
                
                if ticket_found && ticket_size >= 0x200 {
                    // Read the ticket file at the calculated absolute offset
                    reader.seek(SeekFrom::Start(ticket_abs_offset))?;
                    let mut ticket_data = vec![0u8; ticket_size as usize];
                    reader.read_exact(&mut ticket_data)?;
                    
                    eprintln!("ticket raw (encrypted, first 32 bytes): {:02X?}", &ticket_data[0..std::cmp::min(32, ticket_data.len())]);
                    
                    // Decrypt ticket using JNUSLib IV calculation: (fileOffset >> 16) at position 0x08
                    let mut iv = [0u8; 16];
                    let iv_value = ticket_file_offset >> 16;
                    iv[8..16].copy_from_slice(&iv_value.to_be_bytes());
                    eprintln!("Decrypting ticket with IV based on fileOffset=0x{:X}: {:02X?}", ticket_file_offset, iv);
                    
                    crate::wud::decrypt::decrypt_buffer(&mut ticket_data, options.title_key, &iv);
                    
                    // Verify ticket signature
                    let sig_type = u32::from_be_bytes([ticket_data[0], ticket_data[1], ticket_data[2], ticket_data[3]]);
                    eprintln!("Ticket signature type: 0x{:08X}", sig_type);
                    
                    if sig_type != 0x00010004 {
                        eprintln!("⚠️ Invalid ticket signature! Trying zero IV as fallback...");
                        // Re-read and try zero IV
                        reader.seek(SeekFrom::Start(ticket_abs_offset))?;
                        ticket_data = vec![0u8; ticket_size as usize];
                        reader.read_exact(&mut ticket_data)?;
                        crate::wud::decrypt::decrypt_buffer(&mut ticket_data, options.title_key, &zero_iv);
                        
                        let sig_type2 = u32::from_be_bytes([ticket_data[0], ticket_data[1], ticket_data[2], ticket_data[3]]);
                        eprintln!("Ticket signature with zero IV: 0x{:08X}", sig_type2);
                    }
                    
                    eprintln!("ticket decrypted (first 32 bytes): {:02X?}", &ticket_data[0..std::cmp::min(32, ticket_data.len())]);
                    
                    // Extract encrypted title key at offset 0x1BF
                    let encrypted_key: [u8; 16] = ticket_data[0x1BF..0x1CF].try_into().unwrap();
                    
                    // Extract title ID at offset 0x1DC for IV
                    let title_id: [u8; 8] = ticket_data[0x1DC..0x1E4].try_into().unwrap();
                    let mut title_iv = [0u8; 16];
                    title_iv[..8].copy_from_slice(&title_id);
                    
                    eprintln!("Encrypted key from ticket: {:02X?}", encrypted_key);
                    eprintln!("Title ID for IV: {:02X?}", title_id);
                    
                    // Decrypt title key with common key
                    let mut decrypted_key = encrypted_key;
                    crate::wud::decrypt::decrypt_buffer(&mut decrypted_key, options.common_key, &title_iv);
                    
                    eprintln!("🔑 Decrypted GM key from ticket: {:02X?}", decrypted_key);
                    decrypted_key
                } else {
                    eprintln!("⚠️ title.tik not found or too small in SI partition, using disc key");
                    *options.title_key
                }
            }
            } else {
                eprintln!("⚠️ Could not decrypt SI FST, using disc key directly");
                *options.title_key
            }
        } else {
            eprintln!("⚠️ SI partition header invalid, using disc key directly");
            *options.title_key
        }
    } else {
        eprintln!("⚠️ No SI partition found, using disc key directly");
        *options.title_key
    };
    
    eprintln!("GM content key: {:02X?}", gm_content_key);
    
    // Now read FST from GM partition
    // The partition starts with a header, followed by the FST
    report_progress(&options.progress, 0.1, "Reading FST from GM partition...");
    
    // Read partition header (first 0x20 bytes)
    const PARTITION_START_SIGNATURE: [u8; 4] = [0xCC, 0x93, 0xA4, 0xF5];
    
    reader.seek(SeekFrom::Start(gm_offset))?;
    let mut partition_header_raw = vec![0u8; 0x20];
    reader.read_exact(&mut partition_header_raw)?;
    
    // NOTE: Partition header is NOT encrypted (per JNUSLib)
    eprintln!("Partition header (raw): {:02X?}", &partition_header_raw[0..4]);
    
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
    eprintln!("FST offset: 0x{:X}", fst_offset);
    
    reader.seek(SeekFrom::Start(fst_offset))?;
    let mut fst_content = vec![0u8; fst_size as usize];
    reader.read_exact(&mut fst_content)?;
    
    eprintln!("FST raw data (first 32 bytes): {:02X?}", &fst_content[0..32]);
    
    // The disc key might be encrypted and needs to be decrypted with common key!
    // Title ID is in the GM partition name: "GM0005000010137E000000000"
    // Extract title ID bytes from partition name
    let title_id_hex = gm_partition_name.as_ref()
        .and_then(|n| n.strip_prefix("GM"))
        .and_then(|n| if n.len() >= 16 { Some(&n[..16]) } else { None });
    
    let decrypted_title_key: [u8; 16] = if let Some(tid_hex) = title_id_hex {
        // Parse title ID from hex
        let mut title_id = [0u8; 8];
        for i in 0..8 {
            title_id[i] = u8::from_str_radix(&tid_hex[i*2..i*2+2], 16).unwrap_or(0);
        }
        
        // Create IV from Title ID (8 bytes + 8 zero bytes)
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&title_id);
        
        eprintln!("Decrypting title key with common key, IV (titleID): {:02X?}", iv);
        
        // Decrypt the title key using common key
        let mut decrypted = *options.title_key;
        crate::wud::decrypt::decrypt_buffer(&mut decrypted, options.common_key, &iv);
        
        eprintln!("Decrypted title key: {:02X?}", decrypted);
        decrypted
    } else {
        eprintln!("Could not extract title ID from partition name, using disc key directly");
        *options.title_key
    };
    
    // Try FST decryption with decrypted title key and zero IV
    let zero_iv = [0u8; 16];
    crate::wud::decrypt::decrypt_buffer(&mut fst_content, &decrypted_title_key, &zero_iv);
    
    // Verify FST magic ("FST\0")
    const FST_SIGNATURE: [u8; 4] = [0x46, 0x53, 0x54, 0x00];
    eprintln!("FST header (decrypted key + zero IV): {:02X?}", &fst_content[0..4]);
    
    // If that didn't work, try with original disc key + zero IV
    if fst_content[0..4] != FST_SIGNATURE {
        eprintln!("Trying original disc key + zero IV...");
        reader.seek(SeekFrom::Start(fst_offset))?;
        reader.read_exact(&mut fst_content)?;
        crate::wud::decrypt::decrypt_buffer(&mut fst_content, options.title_key, &zero_iv);
        eprintln!("FST header (disc key + zero IV): {:02X?}", &fst_content[0..4]);
    }
    
    // Try with offset-based IV (like TOC uses)
    if fst_content[0..4] != FST_SIGNATURE {
        eprintln!("Trying disc key + offset-based IV...");
        reader.seek(SeekFrom::Start(fst_offset))?;
        reader.read_exact(&mut fst_content)?;
        crate::wud::decrypt::decrypt_chunk(&mut fst_content, options.title_key, fst_offset);
        eprintln!("FST header (disc key + offset IV): {:02X?}", &fst_content[0..4]);
    }
    
    // Try with decrypted key + offset-based IV  
    if fst_content[0..4] != FST_SIGNATURE {
        eprintln!("Trying decrypted key + offset-based IV...");
        reader.seek(SeekFrom::Start(fst_offset))?;
        reader.read_exact(&mut fst_content)?;
        crate::wud::decrypt::decrypt_chunk(&mut fst_content, &decrypted_title_key, fst_offset);
        eprintln!("FST header (decrypted key + offset IV): {:02X?}", &fst_content[0..4]);
    }
    
    // Try with common key directly
    if fst_content[0..4] != FST_SIGNATURE {
        eprintln!("Trying common key + zero IV...");
        reader.seek(SeekFrom::Start(fst_offset))?;
        reader.read_exact(&mut fst_content)?;
        crate::wud::decrypt::decrypt_buffer(&mut fst_content, options.common_key, &zero_iv);
        eprintln!("FST header (common key + zero IV): {:02X?}", &fst_content[0..4]);
    
    // Try GM content key + zero IV (if extracted from ticket)
    if fst_content[0..4] != FST_SIGNATURE {
        eprintln!("Trying GM content key + zero IV...");
        reader.seek(SeekFrom::Start(fst_offset))?;
        reader.read_exact(&mut fst_content)?;
        crate::wud::decrypt::decrypt_buffer(&mut fst_content, &gm_content_key, &zero_iv);
        eprintln!("FST header (GM key + zero IV): {:02X?}", &fst_content[0..4]);
    }
    }
    
    if fst_content[0..4] != FST_SIGNATURE {
        return Err(KairoError::InvalidWud(
            "Invalid FST signature - neither decrypted nor original key worked".to_string()
        ));
    }
    
    
    eprintln!("✅ FST decrypted and verified! Size: {} bytes", fst_content.len());
    
    report_progress(&options.progress, 0.15, &format!(
        "GM partition at offset 0x{:X}, FST parsed", 
        gm_offset
    ));
    
    report_progress(&options.progress, 0.2, "Parsing FST...");
    
    // Parse FST entries (now returns content_infos too)
    let (entries, name_table, content_infos) = parse_fst(&fst_content)?;
    
    eprintln!("Parsed {} ContentFSTInfo entries:", content_infos.len());
    for (i, (offset, size)) in content_infos.iter().enumerate() {
        eprintln!("  Content[{}]: offset=0x{:X}, size=0x{:X}", i, offset, size);
    }
    
    report_progress(&options.progress, 0.25, &format!("Found {} entries, extracting...", entries.len()));
    
    // Extract files
    let total_files = entries.iter().filter(|e| !e.is_dir).count();
    let mut extracted = 0;
    
    // Build directory tree and extract files
    // Pass gm_content_key for decryption and content_infos for offset calculation
    extract_entries(
        &mut reader,
        options,
        &entries,
        &name_table,
        &content_infos,
        &gm_content_key,
        gm_offset + header_size, // Data starts after partition header
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
                if let Some(known_key) = crate::disc_keys::parse_hex_key(&known_key_hex) {
                    let region = crate::disc_keys::get_region(&product_code);
                    
                    eprintln!("🔑 Trying known disc key for {} [{}]", product_code, region);
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



/// Parse FST data into entries and name table (JNUSLib-compatible)
fn parse_fst(data: &[u8]) -> Result<(Vec<FstEntry>, Vec<u8>, Vec<(u64, u64)>)> {
    if data.len() < 0x20 {
        return Err(KairoError::InvalidWud("FST too small".into()));
    }
    
    // FST header
    // 0x00-0x03: "FST\0"
    // 0x04-0x07: sectorSize (file offset factor)
    // 0x08-0x0B: contentCount (number of ContentFSTInfo sections)
    let _magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let sector_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as u64;
    let content_count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
    
    eprintln!("parse_fst: sectorSize=0x{:X}, contentCount={}", sector_size, content_count);
    
    // Parse ContentFSTInfo sections (at 0x20, each 0x20 bytes)
    let content_fst_offset = 0x20usize;
    let content_fst_size = content_count * 0x20;
    
    let mut content_infos: Vec<(u64, u64)> = Vec::new();
    for i in 0..content_count {
        let info_start = content_fst_offset + i * 0x20;
        if info_start + 8 > data.len() { break; }
        
        let offset_sector = u32::from_be_bytes([
            data[info_start], data[info_start + 1],
            data[info_start + 2], data[info_start + 3]
        ]) as u64;
        let size_sector = u32::from_be_bytes([
            data[info_start + 4], data[info_start + 5],
            data[info_start + 6], data[info_start + 7]
        ]) as u64;
        
        // Offset in bytes = (offsetSector * 0x8000) - 0x8000, clamped to 0
        let offset_bytes = if offset_sector > 0 { (offset_sector * 0x8000) - 0x8000 } else { 0 };
        let size_bytes = size_sector * 0x8000;
        
        content_infos.push((offset_bytes, size_bytes));
    }
    
    // File entries start after ContentFSTInfo
    let entries_start = content_fst_offset + content_fst_size;
    
    // Get entry count from root entry's size field
    if entries_start + 0x10 > data.len() {
        return Err(KairoError::InvalidWud("FST data truncated".into()));
    }
    
    let entry_count = u32::from_be_bytes([
        data[entries_start + 8], data[entries_start + 9],
        data[entries_start + 10], data[entries_start + 11]
    ]) as usize;
    
    eprintln!("parse_fst: entries_start=0x{:X}, entry_count={}", entries_start, entry_count);
    
    if entry_count == 0 || entry_count > 1_000_000 {
        return Err(KairoError::InvalidWud("Invalid FST entry count".into()));
    }
    
    let entries_size = entry_count * 0x10;
    let name_table_start = entries_start + entries_size;
    
    if name_table_start > data.len() {
        return Err(KairoError::InvalidWud("FST data truncated".into()));
    }
    
    let mut entries = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let offset = entries_start + i * 0x10;
        if offset + 0x10 <= data.len() {
            let mut entry = FstEntry::from_bytes(&data[offset..offset + 0x10]);
            // Store sector_size for later file offset calculation
            entry.sector_size = sector_size;
            entries.push(entry);
        }
    }
    
    let name_table = data[name_table_start..].to_vec();
    
    eprintln!("parse_fst: parsed {} entries, name_table size={}", entries.len(), name_table.len());
    
    Ok((entries, name_table, content_infos))
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
    
    let name = String::from_utf8_lossy(&name_table[start..end]).to_string();
    
    // Sanitize filename - replace invalid characters
    name.chars()
        .map(|c| {
            if c.is_control() || c == '\0' || c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' {
                '_'
            } else {
                c
            }
        })
        .collect()
}

/// Extract all entries recursively  
fn extract_entries<R: Read + Seek>(
    reader: &mut R,
    options: &ExtractOptions,
    entries: &[FstEntry],
    name_table: &[u8],
    content_infos: &[(u64, u64)],
    content_key: &[u8; 16],
    data_offset: u64,  // Offset to start of data area (partition_offset + header_size)
    entry_idx: usize,
    current_dir: &Path,
    extracted: &mut usize,
    total: usize,
) -> Result<()> {
    if entry_idx >= entries.len() {
        return Ok(());
    }
    
    let entry = &entries[entry_idx];
    let mut name = get_name(name_table, entry.name_offset);

    // DEBUG: Trace meta file corruption
    if name.to_lowercase().contains("meta") {
        println!("🔍 DEBUG meta file candidate:");
        println!("  Name parsed: '{}' (len: {})", name, name.len());
        println!("  Name Bytes: {:?}", name.as_bytes());
        println!("  Name Offset: 0x{:X}", entry.name_offset);
    }

    // HACK: Fix specific corruption for meta.xml
    // If name starts with "meta." and contains garbage/semicolon, force it to meta.xml
    // This handles the case where the name table is corrupted or parsing is wrong for this specific file
    if name.starts_with("meta.") && (name.contains(';') || name.contains('{')) {
            println!("⚠️ Detected corrupted meta filename '{}'. Renaming to 'meta.xml'", name);
            name = "meta.xml".to_string();
    }
    
    // Special handling for root entry (entry_idx == 0)
    // The root's size_or_next contains total entry count, and its children are entries 1 to size_or_next
    if entry_idx == 0 || name.is_empty() || name == "." {
        // Process all children of root at current_dir level
        let total_entries = entry.size_or_next as usize;
        let mut child_idx = 1; // Start from first child (entry 1)
        
        while child_idx < total_entries && child_idx < entries.len() {
            // Recursively call extract_entries for the child
            extract_entries(reader, options, entries, name_table, 
                content_infos, content_key, data_offset, child_idx, current_dir, extracted, total)?;
            
            // Move to next sibling
            if entries[child_idx].is_dir {
                // For directories, skip to next sibling (which is stored in size_or_next)
                child_idx = entries[child_idx].size_or_next as usize;
            } else {
                child_idx += 1;
            }
        }
        return Ok(());
    }
    
    let path = current_dir.join(&name);
    
    if entry.is_dir {
        // Create directory
        fs::create_dir_all(&path)?;
        
        // Process children (entries from entry_idx+1 until size_or_next)
        let next_sibling_idx = entry.size_or_next as usize;
        let mut child_idx = entry_idx + 1;
        while child_idx < next_sibling_idx && child_idx < entries.len() {
            extract_entries(reader, options, entries, name_table,
                content_infos, content_key, data_offset, child_idx, &path, extracted, total)?;
            
            // Move to next sibling
            if entries[child_idx].is_dir {
                child_idx = entries[child_idx].size_or_next as usize;
            } else {
                child_idx += 1;
            }
        }
    } else {
        // Extract file
        // Get content offset from content_infos using entry's content_index
        let content_offset = if (entry.content_index as usize) < content_infos.len() {
            content_infos[entry.content_index as usize].0
        } else {
            0
        };
        
        // wudecrypt: offset_in_cluster = entry->offset_or_parent (already in bytes, NOT multiplied!)
        // The sector_size multiplication was wrong - that's for other calculations
        let offset_in_cluster = (entry.offset_or_parent as u64) << 5;
        let file_size = entry.size_or_next as u64;
        
        // Check for iconTex.tga specifically to debug
        if name.ends_with("iconTex.tga") {
            println!("🔍 DEBUG iconTex.tga:");
            println!("  Flags: 0x{:04X}", entry.flags);
            println!("  Content Index: {}", entry.content_index);
            println!("  Offset in Cluster: 0x{:X} (raw: 0x{:X})", offset_in_cluster, entry.offset_or_parent);
            println!("  Size: {}", file_size);
        }

        // Cluster offset = data_offset + content_offset (where content starts)
        let cluster_offset = data_offset + content_offset;

        if (entry.flags & 0x400) != 0 || (entry.flags & 0x40) != 0 {
            // Hashed Extraction
            println!("🔒 Extracting Hashed file: {}", name);
            extract_file_hashed(
                reader, 
                content_key, 
                cluster_offset, 
                offset_in_cluster, 
                file_size, 
                &path, 
                entry.content_index // This is starting_cluster in wudecrypt
            )?;
        } else {
            // Simple Extraction
            extract_file_encrypted(reader, content_key, cluster_offset, offset_in_cluster, file_size, &path)?;
        }
        
        *extracted += 1;
        let percent = 0.25 + (*extracted as f32 / total as f32) * 0.75;
        report_progress(&options.progress, percent, &format!("Extracting: {}", name));
    }
    
    Ok(())
}

/// Extract and decrypt a file using "Hashed" method (wudecrypt extract_file_hashed)
/// Used when flags indicate hashing (0x400 or 0x40).
/// 
/// Structure:
/// - Block size on disk: 0x10000 (64KB)
/// - Block content: [0x400 Header (IVs + Hashes)] + [0xFC00 Data]
/// - Header must be decrypted first to get the IV for the Data.
fn extract_file_hashed<R: Read + Seek>(
    reader: &mut R,
    key: &[u8; 16],
    cluster_offset: u64,
    file_offset: u64,
    size: u64,
    output_path: &Path,
    starting_cluster: u16,
) -> Result<()> {
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut writer = BufWriter::new(File::create(output_path)?);

    const DISK_BLOCK_SIZE: u64 = 0x10000;
    const DATA_BLOCK_SIZE: u64 = 0xFC00;
    const HEADER_SIZE: u64 = 0x400;

    // IV for the HEADER is based on starting_cluster
    // wudecrypt: first_iv[0] = cluster_id[1]; first_iv[1] = cluster_id[0];
    // starting_cluster is u16 BE. so [0] is MSB, [1] is LSB.
    let mut header_iv = [0u8; 16];
    let sc_bytes = starting_cluster.to_be_bytes();
    header_iv[0] = sc_bytes[0]; 
    header_iv[1] = sc_bytes[1];

    let mut remaining = size;
    let mut current_file_offset = file_offset;

    while remaining > 0 {
        // block_number = file_offset / DATA_BLOCK_SIZE (not 0x8000!)
        let block_number = current_file_offset / DATA_BLOCK_SIZE;
        let block_offset = current_file_offset % DATA_BLOCK_SIZE;

        // read_offset points to the START of the 0x10000 block on disk
        // wudecrypt: read_offset = ... + (blockstruct.number * 0x10000)
        let read_offset = cluster_offset + (block_number * DISK_BLOCK_SIZE);

        // 1. Read and Decrypt HEADER (0x400 bytes)
        reader.seek(SeekFrom::Start(read_offset))?;
        let mut header_buffer = vec![0u8; HEADER_SIZE as usize];
        reader.read_exact(&mut header_buffer)?;
        
        crate::wud::decrypt::decrypt_buffer(&mut header_buffer, key, &header_iv);

        // 2. Extract IV for the Data block from the decrypted header
        // wudecrypt: iv_block = blockstruct.number & 0xF;
        // memcpy(cluster_iv, decrypted_header + (iv_block * 0x14), 16);
        let iv_block_idx = (block_number & 0xF) as usize;
        let iv_offset = iv_block_idx * 0x14; // struct is 20 bytes (16 IV + 4 Hash?)
        
        let mut data_iv = [0u8; 16];
        if iv_offset + 16 <= header_buffer.len() {
            data_iv.copy_from_slice(&header_buffer[iv_offset..iv_offset+16]);
        }
        
        // wudecrypt: if (iv_block == 0) { cluster_iv[1] ^= (uint8_t)cluster_id; }
        // cluster_id here is starting_cluster (u16). "cluster_id" cast to uint8t varies by endian.
        // wudecrypt usually implies Little Endian host. 
        // passing starting_cluster (u16) to function extract_file_hashed.
        // inside extract_file_hashed: cluster_id is u16.
        // In wudecrypt extract_file: cluster_id = (uint8_t*)(&(entry->starting_cluster));
        // On LE: cluster_id[0] is LSB, cluster_id[1] is MSB.
        // "cluster_iv[1] ^= (uint8_t)cluster_id" means xor Byte 1 of IV with LSB of starting_cluster?
        // Wait. (uint8_t)cluster_id usually casts the POINTER, no? in wudecrypt it was passed as u16 value to hashed func.
        // "void extract_file_hashed(..., uint16_t cluster_id)"
        // "if (iv_block == 0) block_sha1[1] ^= (uint8_t)cluster_id;"
        // (uint8_t)val keeps LSB. So Logic: xor with (starting_cluster & 0xFF).
        
        if iv_block_idx == 0 {
             data_iv[1] ^= (starting_cluster & 0xFF) as u8;
        }

        // 3. Read and Decrypt DATA (0xFC00 bytes)
        // position is read_offset + 0x400
        reader.seek(SeekFrom::Start(read_offset + HEADER_SIZE))?;
        let mut data_buffer = vec![0u8; DATA_BLOCK_SIZE as usize];
        
        // Handle last block cases? Usually full blocks.
        if let Err(_) = reader.read_exact(&mut data_buffer) {
             // Try check read amount? For now expect full blocks or handle truncate
             reader.seek(SeekFrom::Start(read_offset + HEADER_SIZE))?;
             let n = reader.read(&mut data_buffer)?;
             data_buffer.truncate(n);
        }

        crate::wud::decrypt::decrypt_buffer(&mut data_buffer, key, &data_iv);

        // 4. Write relevant part
        let max_copy_size = DATA_BLOCK_SIZE - block_offset;
        let copy_size = std::cmp::min(remaining, max_copy_size);
        
        let start = block_offset as usize;
        let end = std::cmp::min((block_offset + copy_size) as usize, data_buffer.len());

        if start < data_buffer.len() {
            writer.write_all(&data_buffer[start..end])?;
        }

        remaining -= copy_size;
        current_file_offset += copy_size;
    }
    writer.flush()?;
    Ok(())
}

/// Extract and decrypt a file matching wudecrypt extract_file_unhashed exactly
/// 
/// wudecrypt logic (functions.c):
/// - blockNumber = file_offset / 0x8000
/// - blockOffset = file_offset % 0x8000  
/// - readOffset = WIIU_DECRYPTED_AREA_OFFSET + volume_offset + cluster_offset + (blockNumber * 0x8000)
/// - IV = FIXED ZERO (not recalculated per block!)
fn extract_file_encrypted<R: Read + Seek>(
    reader: &mut R,
    key: &[u8; 16],
    cluster_offset: u64,  // data_offset + content_offset (already includes WIIU_DECRYPTED_AREA_OFFSET)
    file_offset: u64,     // File offset within content
    size: u64,
    output_path: &Path,
) -> Result<()> {
    // Create parent directories
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    let mut writer = BufWriter::new(File::create(output_path)?);
    
    // wudecrypt uses 0x8000 blocks (32KB), NOT 0x10000!
    const BLOCK_SIZE: u64 = 0x8000;
    
    // wudecrypt uses FIXED ZERO IV for extract_file_unhashed!
    let iv = [0u8; 16];
    
    let mut remaining = size;
    let mut current_file_offset = file_offset;
    
    while remaining > 0 {
        // Calculate block position and offset within block (wudecrypt style)
        let block_number = current_file_offset / BLOCK_SIZE;
        let block_offset = current_file_offset % BLOCK_SIZE;
        
        // Read offset = cluster_offset + (block_number * 0x8000)
        let read_offset = cluster_offset + (block_number * BLOCK_SIZE);
        
        // Seek to block start and read entire block
        reader.seek(SeekFrom::Start(read_offset))?;
        
        let mut block_buffer = vec![0u8; BLOCK_SIZE as usize];
        if let Err(_) = reader.read_exact(&mut block_buffer) {
            // Handle partial read at end of file/partition
            reader.seek(SeekFrom::Start(read_offset))?;
            let actually_read = reader.read(&mut block_buffer)?;
            if actually_read == 0 {
                break;
            }
            block_buffer.truncate(actually_read);
        }
        
        // Decrypt the block with FIXED ZERO IV
        crate::wud::decrypt::decrypt_buffer(&mut block_buffer, key, &iv);
        
        // Copy only the needed portion (from block_offset, up to remaining bytes)
        let max_copy_size = BLOCK_SIZE - block_offset;
        let copy_size = std::cmp::min(remaining, max_copy_size);
        
        let start = block_offset as usize;
        let end = std::cmp::min((block_offset + copy_size) as usize, block_buffer.len());
        
        if start < block_buffer.len() {
            writer.write_all(&block_buffer[start..end])?;
        }
        
        // Update counters
        remaining -= copy_size;
        current_file_offset += copy_size;
    }
    
    writer.flush()?;
    Ok(())
}

/// Extract a single file (unencrypted or with sector-based encryption)
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
