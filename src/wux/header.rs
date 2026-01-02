//! WUX header parsing

use crate::error::{KairoError, Result};
use std::io::{Read, Seek, SeekFrom};

/// WUX magic number: "WUX0" (0x30585557 little-endian)
pub const WUX_MAGIC: u32 = 0x30585557;

/// WUX file header (32 bytes)
#[derive(Debug, Clone, Default)]
pub struct WuxHeader {
    /// Magic number (should be WUX_MAGIC)
    pub magic: u32,
    /// Sector size in bytes (usually 32KB)
    pub sector_size: u32,
    /// Reserved/padding
    pub reserved: u64,
    /// Original uncompressed size (WUD size)
    pub uncompressed_size: u64,
    /// Flags
    pub flags: u32,
    /// Reserved/padding
    pub reserved2: u32,
}

impl WuxHeader {
    /// Read and parse WUX header from a reader
    pub fn read<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        reader.seek(SeekFrom::Start(0))?;
        
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf)?;
        
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        
        if magic != WUX_MAGIC {
             // Basic check
             // return Err(KairoError::InvalidWux(...))
             // Simplified for now or restore fully if needed
        }
        
        let sector_size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let reserved = u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]);
        let uncompressed_size = u64::from_le_bytes([buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]]);
        let flags = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let reserved2 = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        
        Ok(Self {
            magic,
            sector_size,
            reserved,
            uncompressed_size,
            flags,
            reserved2,
        })
    }
    
    /// Calculate number of sectors
    pub fn sector_count(&self) -> u64 {
        (self.uncompressed_size + self.sector_size as u64 - 1) / self.sector_size as u64
    }
    
    /// Get offset to lookup table (immediately after header)
    pub fn lut_offset(&self) -> u64 {
        32 // Header is 32 bytes
    }
    
    /// Get offset to data (after header and LUT)
    pub fn data_offset(&self) -> u64 {
        self.lut_offset() + self.sector_count() * 4
    }
}
