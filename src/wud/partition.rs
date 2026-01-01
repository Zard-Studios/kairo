//! WUD partition table parsing

use crate::error::{KairoError, Result};
use std::io::{Read, Seek, SeekFrom};

/// Partition type identifiers
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PartitionType {
    /// System Information
    SI,
    /// Update Partition
    UP,
    /// Game Information
    GI,
    /// Game Data (main content)
    GM,
    /// Unknown type
    Unknown(u32),
}

impl From<u32> for PartitionType {
    fn from(value: u32) -> Self {
        match value {
            0x5349 => Self::SI, // "SI"
            0x5550 => Self::UP, // "UP"
            0x4749 => Self::GI, // "GI"
            0x474D => Self::GM, // "GM"
            _ => Self::Unknown(value),
        }
    }
}

/// A partition entry
#[derive(Debug, Clone)]
pub struct Partition {
    pub partition_type: PartitionType,
    pub offset: u64,
    pub size: u64,
    pub title_key: Option<[u8; 16]>,
}

/// WUD partition table
#[derive(Debug)]
pub struct PartitionTable {
    pub partitions: Vec<Partition>,
}

impl PartitionTable {
    /// Parse partition table from WUD file
    /// 
    /// The partition table is located at a fixed offset and contains
    /// entries describing each partition's type, offset, and size.
    /// Parse partition table from WUD file
    /// 
    /// The partition table is located at a fixed offset and contains
    /// entries describing each partition's type, offset, and size.
    /// Note: The partition table in retail WUD discs may be encrypted.
    pub fn read<R: Read + Seek>(reader: &mut R, common_key: &[u8; 16]) -> Result<Self> {
        // First try offset 0x18000 (standard location)
        let result = Self::try_read_at(reader, 0x18000, common_key);
        if let Ok(table) = result {
            if !table.partitions.is_empty() {
                return Ok(table);
            }
        }
        
        // If that fails, try scanning for known game partition patterns
        // Retail WUD discs often have the GM partition at 0x10000000
        eprintln!("Standard partition table not found, using fallback offsets");
        
        // Create a synthetic partition table with common offsets
        let partitions = vec![
            Partition {
                partition_type: PartitionType::GM,
                offset: 0x10000000,  // 256MB - common GM offset
                size: 0x500000000,   // ~20GB
                title_key: None,
            }
        ];
        
        Ok(Self { partitions })
    }
    
    fn try_read_at<R: Read + Seek>(
            reader: &mut R, 
            table_offset: u64, 
            common_key: &[u8; 16]
        ) -> Result<Self> {
            reader.seek(SeekFrom::Start(table_offset))?;
            
            let mut raw_entries = Vec::new();
            for _ in 0..4 {
                let mut entry = [0u8; 32];
                reader.read_exact(&mut entry)?;
                raw_entries.push(entry);
            }
            
            // Try different IV candidates
            let iv_candidates: Vec<([u8; 16], &str)> = vec![
                ([0u8; 16], "Zero"),
                ({
                    let mut iv = [0u8; 16];
                    iv[..8].copy_from_slice(&(table_offset / 0x8000).to_be_bytes());
                    (iv, "Sector Index (3)")
                }),
                 ({
                    let mut iv = [0u8; 16];
                    iv[..8].copy_from_slice(&(table_offset).to_be_bytes());
                    (iv, "Offset")
                }),
            ];
            
            for (iv, name) in iv_candidates {
                let mut partitions = Vec::new();
                let mut valid_count = 0;
                
                eprintln!("Trying Partition Table Decryption with IV: {} ({:02X?})", name, &iv[..8]);
                
                for (i, raw) in raw_entries.iter().enumerate() {
                    let mut entry = *raw;
                    crate::wud::decrypt::decrypt_buffer(&mut entry, common_key, &iv);
                    
                    let type_id = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
                    
                    let partition_type = match type_id {
                        0x5349 => PartitionType::SI, // SI
                        0x5550 => PartitionType::UP, // UP
                        0x4749 => PartitionType::GI, // GI
                        0x474D => PartitionType::GM, // GM
                         _ => {
                             // If the first bytes are 0 (unused entry), it's valid but empty
                             if type_id == 0 {
                                 continue;
                             }
                             // Invalid type
                             // eprintln!("  Entry {} invalid type: {:08X}", i, type_id);
                             break; 
                         },
                    };
                    
                    valid_count += 1;
                    
                     let offset = u64::from_be_bytes([
                        entry[4], entry[5], entry[6], entry[7],
                        entry[8], entry[9], entry[10], entry[11],
                    ]);
                    
                    let size = u64::from_be_bytes([
                        entry[12], entry[13], entry[14], entry[15],
                        entry[16], entry[17], entry[18], entry[19],
                    ]);
                    
                    eprintln!("  Found {} partition at 0x{:X}, size {}", 
                        match partition_type { 
                            PartitionType::SI => "SI",
                            PartitionType::UP => "UP", 
                            PartitionType::GI => "GI",
                            PartitionType::GM => "GM",
                            _ => "??",
                        }, offset, size);
                        
                    partitions.push(Partition {
                        partition_type,
                        offset,
                        size,
                        title_key: None,
                    });
                }
                
                // If we found at least one valid partition, return it
                if valid_count > 0 {
                    eprintln!("Successfully decrypted partition table with IV: {}", name);
                    return Ok(Self { partitions });
                }
            }
            
            Ok(Self { partitions: Vec::new() })
        }
    
    /// Find the GM (game data) partition
    pub fn game_partition(&self) -> Option<&Partition> {
        self.partitions.iter().find(|p| p.partition_type == PartitionType::GM)
    }
}
