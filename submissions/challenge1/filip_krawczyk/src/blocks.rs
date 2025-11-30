use std::ops::{Deref, DerefMut};

/// Represents a sequence of blocks of a given size.
/// Its length (number of bytes) is guaranteed to be a multiple of BLOCK_SIZE_BYTES.
#[derive(Clone)]
pub struct Blocks<const BLOCK_SIZE_BYTES: u8>(Vec<u8>);

impl<const BLOCK_SIZE_BYTES: u8> Blocks<BLOCK_SIZE_BYTES> {
    /// Creates a new Blocks instance from a vector of bytes.
    /// Returns an error if the length of the vector is not a multiple of BLOCK_SIZE_BYTES.
    pub fn new(data: Vec<u8>) -> Result<Self, BlocksError> {
        if data.len() % (BLOCK_SIZE_BYTES as usize) != 0 {
            return Err(BlocksError);
        }
        Ok(Blocks(data))
    }

    /// Returns the number of blocks in the sequence.
    pub fn block_count(&self) -> usize {
        self.0.len() / BLOCK_SIZE_BYTES as usize
    }

    /// Returns a mutable reference to the n-th block in the sequence.
    pub fn nth_block_mut(&mut self, n: usize) -> Option<&mut [u8]> {
        let start_index = n * BLOCK_SIZE_BYTES as usize;
        let end_index = start_index + BLOCK_SIZE_BYTES as usize;
        self.0.get_mut(start_index..end_index)
    }

    /// Returns a mutable reference to the byte at the given block index and byte index.
    pub fn get_byte(&mut self, block_index: usize, bytes_index: usize) -> Option<&mut u8> {
        self.0
            .get_mut(block_index * BLOCK_SIZE_BYTES as usize + bytes_index)
    }

    /// Removes the last block from the sequence and returns it.
    pub fn pop_block(&mut self) -> Option<Box<[u8]>> {
        if self.0.len() < BLOCK_SIZE_BYTES as usize {
            return None;
        }
        Some(
            self.0
                .drain(self.0.len() - BLOCK_SIZE_BYTES as usize..)
                .collect::<Vec<u8>>()
                .into_boxed_slice(),
        )
    }
}

impl<const BLOCK_SIZE_BYTES: u8> Deref for Blocks<BLOCK_SIZE_BYTES> {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const BLOCK_SIZE_BYTES: u8> DerefMut for Blocks<BLOCK_SIZE_BYTES> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const BLOCK_SIZE_BYTES: u8> std::fmt::Debug for Blocks<BLOCK_SIZE_BYTES> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, byte) in self.iter().enumerate() {
            if i % BLOCK_SIZE_BYTES as usize == 0 && i != 0 {
                write!(f, " | ")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Invalid blocks")]
pub struct BlocksError;

pub type AesBlocks = Blocks<16>;

impl AesBlocks {
    /// Returns an iterator that yields each block in the sequence as a slice of 16 bytes.
    pub fn iter_blocks(&self) -> impl Iterator<Item = &[u8; 16]> {
        self.0.chunks(16).map(|chunk| chunk.try_into().unwrap())
    }
}
