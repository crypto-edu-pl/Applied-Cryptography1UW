const BLOCK_SIZE: usize = 16;

pub fn padding_oracle_attack(
    iv: &[u8],
    ctx: &[u8],
    oracle: impl Fn(&[u8], &[u8]) -> bool,
) -> Option<Vec<u8>> {
    let mut tmp = iv.to_vec();
    tmp.extend_from_slice(ctx);
    let ctx = tmp;

    let mut ptx = ctx.clone();
    let mut query = ctx.clone();

    for i in (BLOCK_SIZE..ctx.len()).rev() {
        let pad = BLOCK_SIZE - i % BLOCK_SIZE;
        let pad: u8 = pad.try_into().unwrap();

        let mut found = false;

        for k in 0..(pad - 1) {
            let offset = i + 1 + k as usize;
            query[offset - BLOCK_SIZE] = ptx[offset] ^ ctx[offset - BLOCK_SIZE] ^ pad;
        }

        for j in 0..=u8::MAX {
            query[i - BLOCK_SIZE] = j;

            if !oracle(&query[..BLOCK_SIZE], &query[BLOCK_SIZE..]) {
                continue;
            }

            if pad == 1 {
                query[i - BLOCK_SIZE - 1] ^= u8::MAX;

                let res = oracle(&query[..BLOCK_SIZE], &query[BLOCK_SIZE..]);

                query[i - BLOCK_SIZE - 1] ^= u8::MAX;

                if !res {
                    continue;
                }
            }

            found = true;

            ptx[i] = query[i - BLOCK_SIZE] ^ pad ^ ctx[i - BLOCK_SIZE];
        }

        if !found {
            return None;
        }

        if pad as usize == BLOCK_SIZE {
            query.truncate(query.len() - BLOCK_SIZE);

            //for j in (query.len() - BLOCK_SIZE)..query.len() {
            //    query[j] = ctx[j];
            //}

            let query_len = query.len();

            query[(query_len - BLOCK_SIZE)..]
                .copy_from_slice(&ctx[(query_len - BLOCK_SIZE)..query_len]);
        }
    }

    Some(ptx[BLOCK_SIZE..].to_vec())
}
