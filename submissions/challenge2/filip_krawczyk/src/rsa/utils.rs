use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

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
}
