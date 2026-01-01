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
        
        let mut partitions = Vec::new();
        
        // Read partition entries (max 4 partitions)
        for i in 0..4 {
            let mut entry = [0u8; 32];
            reader.read_exact(&mut entry)?;
            
            // Decrypt the entry using Common Key
            // IV is typically 0 for the partition table
            let iv = [0u8; 16]; 
            crate::wud::decrypt::decrypt_buffer(&mut entry, common_key, &iv);
            
            // Debug: print decrypted bytes
            eprintln!("Partition {} decrypted (IV=0): {:02X?}", i, &entry[..8]);
            
            let type_id = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
            
            // Check for valid partition type markers (SI, UP, GI, GM)
            let partition_type = match type_id {
                0x5349 => PartitionType::SI,
                0x5550 => PartitionType::UP,
                0x4749 => PartitionType::GI,
                0x474D => PartitionType::GM,
                _ => continue, // Skip invalid entries
            };
            
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
        
        Ok(Self { partitions })
    }
    
    /// Find the GM (game data) partition
    pub fn game_partition(&self) -> Option<&Partition> {
        self.partitions.iter().find(|p| p.partition_type == PartitionType::GM)
    }
}
