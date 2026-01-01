//! WUX to WUD decompression

use crate::error::Result;
use super::WuxHeader;
use std::io::{Read, Write, Seek, SeekFrom, BufReader, BufWriter};
use std::fs::File;
use std::path::Path;

/// Progress callback type
pub type ProgressFn = Box<dyn Fn(f32, &str) + Send>;

/// Decompress a WUX file to WUD format
pub fn decompress_wux<P: AsRef<Path>>(
    input: P,
    output: P,
    on_progress: Option<ProgressFn>,
) -> Result<()> {
    let mut reader = BufReader::new(File::open(input)?);
    let mut writer = BufWriter::new(File::create(output)?);
    
    // Read header
    let header = WuxHeader::read(&mut reader)?;
    let sector_count = header.sector_count() as usize;
    let sector_size = header.sector_size as usize;
    
    // Read lookup table (LUT)
    reader.seek(SeekFrom::Start(header.lut_offset()))?;
    let mut lut = vec![0u32; sector_count];
    for i in 0..sector_count {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        lut[i] = u32::from_le_bytes(buf);
    }
    
    // Decompress sectors
    let data_offset = header.data_offset();
    let mut sector_buf = vec![0u8; sector_size];
    
    for (i, &lut_entry) in lut.iter().enumerate() {
        // Calculate source position
        let src_offset = data_offset + (lut_entry as u64) * (sector_size as u64);
        reader.seek(SeekFrom::Start(src_offset))?;
        
        // Read and write sector
        reader.read_exact(&mut sector_buf)?;
        writer.write_all(&sector_buf)?;
        
        // Report progress
        if let Some(ref callback) = on_progress {
            let percent = (i + 1) as f32 / sector_count as f32;
            callback(percent, &format!("Sector {}/{}", i + 1, sector_count));
        }
    }
    
    writer.flush()?;
    Ok(())
}
