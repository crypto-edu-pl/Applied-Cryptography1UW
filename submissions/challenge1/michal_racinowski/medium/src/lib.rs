use easy::xor_with;

const BLOCK_SIZE: usize = 16;

pub fn cbc_bit_flipping_attack(
    prefix: &[u8],
    _suffix: &[u8],
    target: &[u8],
    mut oracle: impl FnMut(&[u8]) -> Option<(Vec<u8>, Vec<u8>)>,
) -> Option<(Vec<u8>, Vec<u8>)> {
    if target.len() != BLOCK_SIZE {
        return None;
    }

    let prefix_len = prefix.len() + BLOCK_SIZE - prefix.len() % BLOCK_SIZE;

    let mut query = vec![0x41; prefix_len - prefix.len()];
    query.extend_from_slice(&[0x42; BLOCK_SIZE]);
    query.extend_from_slice(&[0x43; BLOCK_SIZE]);

    let (iv, mut ctx) = oracle(&query)?;

    let mut block = ctx.split_off(prefix_len);
    let mut rest = block.split_off(BLOCK_SIZE);

    xor_with(&mut block, target);
    xor_with(&mut block, &[0x43; BLOCK_SIZE]);

    ctx.append(&mut block);
    ctx.append(&mut rest);

    Some((iv, ctx))
}
