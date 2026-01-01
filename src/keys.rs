//! Key loading and validation

use crate::error::{KairoError, Result};
use std::fs;
use std::path::Path;

/// A 16-byte AES key
pub type Key = [u8; 16];

/// Load a key from a binary file
pub fn load_key_file(path: &Path) -> Result<Key> {
    let data = fs::read(path)?;
    
    if data.len() != 16 {
        return Err(KairoError::InvalidKey(
            format!("Expected 16 bytes, got {}", data.len())
        ));
    }
    
    let mut key = [0u8; 16];
    key.copy_from_slice(&data);
    Ok(key)
}

/// Parse a key from a hex string (32 characters)
pub fn parse_key_hex(hex: &str) -> Result<Key> {
    let hex = hex.trim();
    
    if hex.len() != 32 {
        return Err(KairoError::InvalidKey(
            format!("Expected 32 hex characters, got {}", hex.len())
        ));
    }
    
    let bytes: Vec<u8> = (0..32)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| KairoError::InvalidKey("Invalid hex characters".into()))?;
    
    let mut key = [0u8; 16];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_valid_hex() {
        let hex = "00112233445566778899AABBCCDDEEFF";
        let key = parse_key_hex(hex).unwrap();
        assert_eq!(key[0], 0x00);
        assert_eq!(key[15], 0xFF);
    }
    
    #[test]
    fn test_parse_invalid_hex_length() {
        let hex = "0011223344";
        assert!(parse_key_hex(hex).is_err());
    }
}
