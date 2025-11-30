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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_mut_empty() {
        let mut data = vec![];
        pad_mut(&mut data, 16);
        assert_eq!(data.len(), 16);
        assert!(data.iter().all(|&b| b == 16));
    }

    #[test]
    fn test_pad_mut_exact_block_size() {
        let mut data = vec![0u8; 16];
        pad_mut(&mut data, 16);
        assert_eq!(data.len(), 32);
        assert!(data[16..].iter().all(|&b| b == 16));
    }

    #[test]
    fn test_pad_mut_partial_block() {
        let mut data = vec![1, 2, 3];
        pad_mut(&mut data, 16);
        assert_eq!(data.len(), 16);
        assert_eq!(data[0..3], [1, 2, 3]);
        assert!(data[3..].iter().all(|&b| b == 13));
    }

    #[test]
    fn test_pad_mut_one_byte_short() {
        let mut data = vec![0u8; 15];
        pad_mut(&mut data, 16);
        assert_eq!(data.len(), 16);
        assert_eq!(data[15], 1);
    }

    #[test]
    fn test_pad_mut_multiple_blocks() {
        let mut data = vec![0u8; 32];
        pad_mut(&mut data, 16);
        assert_eq!(data.len(), 48);
        assert!(data[32..].iter().all(|&b| b == 16));
    }

    #[test]
    fn test_pad_mut_different_block_sizes() {
        let mut data = vec![1, 2];
        pad_mut(&mut data, 4);
        assert_eq!(data.len(), 4);
        assert_eq!(data, vec![1, 2, 2, 2]);

        let mut data = vec![1, 2, 3, 4, 5];
        pad_mut(&mut data, 8);
        assert_eq!(data.len(), 8);
        assert_eq!(data[5..], [3, 3, 3]);
    }

    #[test]
    fn test_pad() {
        let data = vec![1, 2, 3];
        let blocks = pad::<16>(&data);
        assert_eq!(blocks.len(), 16);
        assert_eq!(&blocks[0..3], &[1, 2, 3]);
        assert!(blocks[3..].iter().all(|&b| b == 13));
    }

    #[test]
    fn test_unpad_mut_valid() {
        let mut data = vec![1, 2, 3, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13];
        unpad_mut(&mut data, 16).unwrap();
        assert_eq!(data, vec![1, 2, 3]);
    }

    #[test]
    fn test_unpad_mut_full_block_padding() {
        let mut data = vec![16u8; 16];
        unpad_mut(&mut data, 16).unwrap();
        assert_eq!(data, vec![]);
    }

    #[test]
    fn test_unpad_mut_single_byte_padding() {
        let mut data = vec![0u8; 15];
        data.push(1);
        unpad_mut(&mut data, 16).unwrap();
        assert_eq!(data, vec![0u8; 15]);
    }

    #[test]
    fn test_unpad_mut_not_multiple_of_block_size() {
        let mut data = vec![1, 2, 3];
        assert!(unpad_mut(&mut data, 16).is_err());
    }

    #[test]
    fn test_unpad_mut_empty() {
        let mut data = vec![];
        assert!(unpad_mut(&mut data, 16).is_err());
    }

    #[test]
    fn test_unpad_mut_invalid_padding_byte_zero() {
        let mut data = vec![0u8; 16];
        assert!(unpad_mut(&mut data, 16).is_err());
    }

    #[test]
    fn test_unpad_mut_invalid_padding_byte_too_large() {
        let mut data = vec![0u8; 31];
        data.push(17); // padding byte > block_size
        assert!(unpad_mut(&mut data, 16).is_err());
    }

    #[test]
    fn test_unpad_mut_invalid_padding_byte_mismatch() {
        let mut data = vec![0u8; 14];
        data.push(3);
        data.push(2); // padding bytes not all the same
        assert!(unpad_mut(&mut data, 16).is_err());
    }

    #[test]
    fn test_unpad_mut_padding_length_exceeds_data() {
        let mut data = vec![0u8; 10];
        data.push(16); // padding byte says 16, but data is only 11 bytes
        assert!(unpad_mut(&mut data, 16).is_err());
    }

    #[test]
    fn test_unpad() {
        let data = vec![1, 2, 3, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13];
        let blocks = Blocks::new(data).unwrap();
        let unpadded = unpad::<16>(&blocks).unwrap();
        assert_eq!(unpadded, vec![1, 2, 3]);
    }

    #[test]
    fn test_round_trip_pad_unpad() {
        let original = vec![1, 2, 3, 4, 5];
        let padded = pad::<16>(&original);
        let unpadded = unpad::<16>(&padded).unwrap();
        assert_eq!(unpadded, original);
    }

    #[test]
    fn test_round_trip_empty() {
        let original = vec![];
        let padded = pad::<16>(&original);
        let unpadded = unpad::<16>(&padded).unwrap();
        assert_eq!(unpadded, original);
    }

    #[test]
    fn test_round_trip_exact_block_size() {
        let original = vec![0u8; 16];
        let padded = pad::<16>(&original);
        let unpadded = unpad::<16>(&padded).unwrap();
        assert_eq!(unpadded, original);
    }

    #[test]
    fn test_round_trip_multiple_blocks() {
        let original = vec![0u8; 32];
        let padded = pad::<16>(&original);
        let unpadded = unpad::<16>(&padded).unwrap();
        assert_eq!(unpadded, original);
    }

    #[test]
    fn test_round_trip_different_block_sizes() {
        let original = vec![1, 2, 3, 4, 5];
        let padded = pad::<8>(&original);
        let unpadded = unpad::<8>(&padded).unwrap();
        assert_eq!(unpadded, original);

        let original = vec![1, 2];
        let padded = pad::<4>(&original);
        let unpadded = unpad::<4>(&padded).unwrap();
        assert_eq!(unpadded, original);
    }

    #[test]
    fn test_unpad_mut_mixed_content() {
        let mut data = vec![
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x05, 0x05, 0x05,
            0x05, 0x05,
        ];
        unpad_mut(&mut data, 16).unwrap();
        assert_eq!(data, b"Hello World");
    }

    #[test]
    fn test_round_trip_multiple_sizes() {
        let mut data = Vec::new();
        for i in 0..100 {
            let padded = pad::<16>(&data);
            // At least one byte + ceil to 16
            assert_eq!(padded.len(), ((i + 1) as usize).div_ceil(16) * 16);
            let unpadded = unpad::<16>(&padded).unwrap();
            assert_eq!(unpadded, data);
            data.push(i as u8);
        }
    }
}
