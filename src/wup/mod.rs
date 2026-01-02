//! WUP format extraction and packing
//! 
//! Extracts decrypted Wii U content to WUP Installer compatible format.
//! Also can pack code/content/meta back to installable WUP format.

mod extract;
pub mod pack;

pub use extract::{extract_wud_to_wup, ExtractOptions, ProgressCallback};
pub use pack::pack_to_wup;
