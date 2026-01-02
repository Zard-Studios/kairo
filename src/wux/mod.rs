//! WUX file format handling
//! 
//! WUX is a compressed WUD format using a sector lookup table (LUT).

mod header;
mod decompress;

pub use header::WuxHeader;
// pub use decompress::decompress_wux;
