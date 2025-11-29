use std::ops::Deref;

/// It's length is guaranteed to be a multiple of BLOCK_SIZE_BYTES.
#[derive(Clone)]
pub struct Blocks<const BLOCK_SIZE_BYTES: u8>(Vec<u8>);

impl<const BLOCK_SIZE_BYTES: u8> Blocks<BLOCK_SIZE_BYTES> {
    pub fn new(data: Vec<u8>) -> Result<Self, BlocksError> {
        if data.len() % (BLOCK_SIZE_BYTES as usize) != 0 {
            return Err(BlocksError);
        }
        Ok(Blocks(data))
    }
}

impl<const BLOCK_SIZE_BYTES: u8> Deref for Blocks<BLOCK_SIZE_BYTES> {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
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
    pub fn iter_blocks(&self) -> impl Iterator<Item = &[u8; 16]> {
        self.0.chunks(16).map(|chunk| chunk.try_into().unwrap())
    }
}
