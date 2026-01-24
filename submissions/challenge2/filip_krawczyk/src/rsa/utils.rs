use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

/// Integer cube root using binary search
/// Returns the largest integer r such that r^3 <= n
pub fn integer_cube_root(n: &BigUint) -> BigUint {
    if n.is_zero() {
        return BigUint::zero();
    }
    if n.is_one() {
        return BigUint::one();
    }

    // Binary search for cube root
    let mut low = BigUint::one();
    let mut high = n.clone();

    while &low < &high {
        let mid = (&low + &high + BigUint::one()) >> 1;
        let mid_cubed = &mid * &mid * &mid;

        if &mid_cubed <= n {
            low = mid;
        } else {
            high = mid - BigUint::one();
        }
    }

    low
}

/// Chinese Remainder Theorem for three residues
/// Given c_i = x mod n_i for i in 0,1,2, find x mod (n_0 * n_1 * n_2)
pub fn crt_three(
    c0: &BigUint,
    n0: &BigUint,
    c1: &BigUint,
    n1: &BigUint,
    c2: &BigUint,
    n2: &BigUint,
) -> BigUint {
    // N_012 = n_0 * n_1 * n_2
    let n_012 = n0 * n1 * n2;

    // m_s_0 = n_1 * n_2 (product of all moduli except n_0)
    // m_s_1 = n_0 * n_2
    // m_s_2 = n_0 * n_1
    let m_s_0 = n1 * n2;
    let m_s_1 = n0 * n2;
    let m_s_2 = n0 * n1;

    // result = sum of (c_i * m_s_i * invmod(m_s_i, n_i)) mod N_012
    let term0 = c0 * &m_s_0 * invmod(&m_s_0, n0).expect("m_s_0 and n_0 should be coprime");
    let term1 = c1 * &m_s_1 * invmod(&m_s_1, n1).expect("m_s_1 and n_1 should be coprime");
    let term2 = c2 * &m_s_2 * invmod(&m_s_2, n2).expect("m_s_2 and n_2 should be coprime");

    (term0 + term1 + term2) % n_012
}

/// Modular exponentiation using square-and-multiply algorithm
/// Computes (base^exp) % modulus efficiently
pub fn modexp(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus.is_one() {
        return BigUint::zero();
    }

    let mut result = BigUint::one();
    let mut base = base % modulus;
    let mut exp = exp.clone();

    while !exp.is_zero() {
        if &exp % 2u32 == BigUint::one() {
            result = (&result * &base) % modulus;
        }
        base = (&base * &base) % modulus;
        exp >>= 1;
    }

    result
}

/// Extended Euclidean Algorithm
/// Returns (gcd, x, y) such that a*x + b*y = gcd(a, b)
pub fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() {
        return (a.clone(), BigInt::one(), BigInt::zero());
    }

    let (gcd, x1, y1) = egcd(b, &(a % b));
    let x = y1.clone();
    let y = x1 - (a / b) * &y1;

    (gcd, x, y)
}

/// Modular multiplicative inverse
/// Returns x such that (a * x) % m == 1
/// Returns None if inverse doesn't exist (gcd(a, m) != 1)
pub fn invmod(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a_int = BigInt::from(a.clone());
    let m_int = BigInt::from(m.clone());

    let (gcd, x, _) = egcd(&a_int, &m_int);

    if !gcd.is_one() {
        return None;
    }

    let result = ((x % &m_int) + &m_int) % &m_int;
    Some(result.to_biguint().expect("Result should be positive"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invmod_example() {
        // invmod(17, 3120) should be 2753
        let a = BigUint::from(17u32);
        let m = BigUint::from(3120u32);
        let result = invmod(&a, &m).unwrap();
        assert_eq!(result, BigUint::from(2753u32));

        // Verify: (17 * 2753) % 3120 == 1
        let check = (&a * &result) % &m;
        assert_eq!(check, BigUint::one());
    }

    #[test]
    fn test_invmod_e3() {
        // Test with e=3, which is common in RSA
        // For p=5, q=11: n=55, et=(5-1)*(11-1)=40
        let e = BigUint::from(3u32);
        let et = BigUint::from(40u32);
        let d = invmod(&e, &et).unwrap();

        // Verify: (3 * d) % 40 == 1
        let check = (&e * &d) % &et;
        assert_eq!(check, BigUint::one());
    }

    #[test]
    fn test_modexp() {
        // 2^10 % 1000 = 1024 % 1000 = 24
        let base = BigUint::from(2u32);
        let exp = BigUint::from(10u32);
        let modulus = BigUint::from(1000u32);
        assert_eq!(modexp(&base, &exp, &modulus), BigUint::from(24u32));
    }

    #[test]
    fn test_integer_cube_root() {
        // 27^(1/3) = 3
        assert_eq!(
            integer_cube_root(&BigUint::from(27u32)),
            BigUint::from(3u32)
        );

        // 26^(1/3) = 2 (floor)
        assert_eq!(
            integer_cube_root(&BigUint::from(26u32)),
            BigUint::from(2u32)
        );

        // 64^(1/3) = 4
        assert_eq!(
            integer_cube_root(&BigUint::from(64u32)),
            BigUint::from(4u32)
        );

        // 1000^(1/3) = 10
        assert_eq!(
            integer_cube_root(&BigUint::from(1000u32)),
            BigUint::from(10u32)
        );

        // 42^3 = 74088
        let m = BigUint::from(42u32);
        let m_cubed = &m * &m * &m;
        assert_eq!(integer_cube_root(&m_cubed), m);
    }

    #[test]
    fn test_crt_three() {
        // Simple example: find x where x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7)
        // x = 23 satisfies all three
        let result = crt_three(
            &BigUint::from(2u32),
            &BigUint::from(3u32),
            &BigUint::from(3u32),
            &BigUint::from(5u32),
            &BigUint::from(2u32),
            &BigUint::from(7u32),
        );
        assert_eq!(result, BigUint::from(23u32));
    }
}
