use aes::Aes128;
use aes::cipher::{
    BlockDecrypt, BlockEncrypt, BlockSizeUser, InvalidLength, KeyInit, generic_array::GenericArray,
};

pub fn xor_with(buffer: &mut [u8], other: &[u8]) {
    for (a, b) in std::iter::zip(&mut *buffer, other) {
        *a ^= b;
    }
}

pub fn split_to_blocks(
    mut data: &mut [u8],
) -> Option<Vec<&mut GenericArray<u8, <Aes128 as BlockSizeUser>::BlockSize>>> {
    let mut blocks = Vec::new();

    for _ in (0..data.len()).step_by(16) {
        let (block, rest) = data.split_at_mut(16);

        blocks.push(GenericArray::from_mut_slice(block));
        data = rest;
    }

    Some(blocks)
}

pub struct Aes128Cbc {
    cipher: Aes128,
    iv: GenericArray<u8, <Aes128 as BlockSizeUser>::BlockSize>,
}

impl Aes128Cbc {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        Ok(Self {
            cipher: Aes128::new_from_slice(key)?,
            iv: *GenericArray::from_slice(iv),
        })
    }

    pub fn encrypt(&self, ptx: &[u8]) -> Vec<u8> {
        let pad = 16 - ptx.len() % 16;
        let pad: u8 = pad.try_into().unwrap();

        let mut ctx = ptx.to_vec();
        for _ in 0..(pad as usize) {
            ctx.push(pad);
        }

        let mut blocks = split_to_blocks(&mut ctx).unwrap();

        for i in 0..blocks.len() {
            let prev = if i == 0 { self.iv } else { *blocks[i - 1] };

            xor_with(blocks[i], &prev);
            self.cipher.encrypt_block(blocks[i]);
        }

        ctx
    }

    pub fn decrypt(&self, ctx: &[u8]) -> Option<Vec<u8>> {
        let mut ptx = ctx.to_vec();

        let mut blocks = split_to_blocks(&mut ptx)?;

        for i in (0..blocks.len()).rev() {
            let prev = if i == 0 { self.iv } else { *blocks[i - 1] };

            self.cipher.decrypt_block(blocks[i]);
            xor_with(blocks[i], &prev);
        }

        let pad = ptx[ptx.len() - 1];

        if !(1..=16).contains(&pad) {
            return None;
        }

        for _ in 0..(pad as usize) {
            if ptx.pop() != Some(pad) {
                return None;
            }
        }

        Some(ptx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let mut left = Vec::from_iter(1_u8..22);
        let right = [42_u8; 22].to_vec();
        xor_with(&mut left, &right);
        assert_eq!(
            left,
            [
                43, 40, 41, 46, 47, 44, 45, 34, 35, 32, 33, 38, 39, 36, 37, 58, 59, 56, 57, 62, 63
            ]
        )
    }

    #[test]
    fn test_split_to_blocks() {
        let mut data = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        assert_eq!(
            split_to_blocks(&mut data),
            Some(vec![
                GenericArray::from_mut_slice(&mut [
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
                ]),
                GenericArray::from_mut_slice(&mut [
                    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
                ]),
            ])
        );
    }
}
