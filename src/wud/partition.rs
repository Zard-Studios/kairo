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
    pub fn read<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        // WUD partition table starts at offset 0x18000
        const PARTITION_TABLE_OFFSET: u64 = 0x18000;
        
        reader.seek(SeekFrom::Start(PARTITION_TABLE_OFFSET))?;
        
        let mut partitions = Vec::new();
        
        // Read partition entries (max 4 partitions)
        for _ in 0..4 {
            let mut entry = [0u8; 32];
            reader.read_exact(&mut entry)?;
            
            let type_id = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
            
            // Skip empty entries
            if type_id == 0 {
                continue;
            }
            
            let offset = u64::from_be_bytes([
                entry[4], entry[5], entry[6], entry[7],
                entry[8], entry[9], entry[10], entry[11],
            ]);
            
            let size = u64::from_be_bytes([
                entry[12], entry[13], entry[14], entry[15],
                entry[16], entry[17], entry[18], entry[19],
            ]);
            
            partitions.push(Partition {
                partition_type: PartitionType::from(type_id),
                offset,
                size,
                title_key: None,
            });
        }
        
        if partitions.is_empty() {
            return Err(KairoError::InvalidWud("No partitions found".into()));
        }
        
        Ok(Self { partitions })
    }
    
    /// Find the GM (game data) partition
    pub fn game_partition(&self) -> Option<&Partition> {
        self.partitions.iter().find(|p| p.partition_type == PartitionType::GM)
    }
}
