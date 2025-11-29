use std::iter;

use thiserror::Error;

use crate::blocks::Blocks;

pub fn pad_mut(data: &mut Vec<u8>, block_size: u8) {
    let last_block_fill_size = (data.len() % (block_size as usize)) as u8; // within range [0, block_size-1]
    let padding_size = block_size - last_block_fill_size; // within range [1, block_size]
    data.extend(iter::repeat_n(padding_size, padding_size as usize));
}

pub fn pad<const BLOCK_SIZE_BYTES: u8>(data: &[u8]) -> Blocks<BLOCK_SIZE_BYTES> {
    let mut padded = data.to_vec();
    pad_mut(&mut padded, BLOCK_SIZE_BYTES);
    // This is safe because the length of the padded data is guaranteed to be a multiple of BLOCK_SIZE_BYTES
    Blocks::new(padded).unwrap()
}

pub fn unpad_mut(data: &mut Vec<u8>, block_size: u8) -> Result<(), Pkcs7PaddingError> {
    if data.len() % (block_size as usize) != 0 {
        return Err(Pkcs7PaddingError);
    }
    let Some(padding_byte) = data.last() else {
        // Even empty data is padded to non-empty vector, so empty padded data is invalid
        return Err(Pkcs7PaddingError);
    };
    if !(1..=block_size).contains(padding_byte) {
        return Err(Pkcs7PaddingError);
    }
    if data.len() < *padding_byte as usize {
        return Err(Pkcs7PaddingError);
    }
    if !data
        .iter()
        .rev()
        .take(*padding_byte as usize)
        .all(|b| b == padding_byte)
    {
        return Err(Pkcs7PaddingError);
    }
    data.truncate(data.len() - *padding_byte as usize);
    Ok(())
}

pub fn unpad<const BLOCK_SIZE_BYTES: u8>(
    data: &Blocks<BLOCK_SIZE_BYTES>,
) -> Result<Vec<u8>, Pkcs7PaddingError> {
    let mut unpadded = data.to_vec();
    unpad_mut(&mut unpadded, BLOCK_SIZE_BYTES)?;
    Ok(unpadded)
}

#[derive(Debug, Error)]
#[error("Invalid PKCS#7 padding")]
pub struct Pkcs7PaddingError;

// TODO: tests
