//! Error types for KAIRO

use thiserror::Error;

#[derive(Error, Debug)]
pub enum KairoError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Invalid WUX file: {0}")]
    InvalidWux(String),
    
    #[error("Invalid WUD file: {0}")]
    InvalidWud(String),
    
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    #[error("Decryption failed: {0}")]
    Decryption(String),
    
    #[error("Hash verification failed")]
    HashMismatch,
}

pub type Result<T> = std::result::Result<T, KairoError>;
