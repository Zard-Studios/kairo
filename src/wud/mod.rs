//! WUD file format handling
//! 
//! WUD files contain encrypted Wii U disc data with multiple partitions.

mod partition;
mod decrypt;

pub use partition::{PartitionTable, Partition, PartitionType};
pub use decrypt::decrypt_partition;
