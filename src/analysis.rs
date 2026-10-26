use crate::{
    crypto::{bignum, biguint, verify_private},
    import::public_key,
    model::Target,
};
use anyhow::{Result, ensure};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use openssl::{
    pkey::{Id, PKey},
    rsa::Rsa,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Analysis {
    pub target_id: String,
    pub algorithm: String,
    pub checks: Vec<String>,
    pub outcome: String,
    pub method: Option<String>,
    pub finding_id: Option<i64>,
    #[serde(skip)]
    pub private_pem: Option<Vec<u8>>,
}

fn inverse(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    let a = a.to_bigint()?;
    let n = n.to_bigint()?;
    let g = a.extended_gcd(&n);
    if g.gcd != BigInt::one() {
        return None;
    }
    g.x.mod_floor(&n).to_biguint()
}

pub fn rsa_private(target: &Target, p: &BigUint, q: &BigUint) -> Result<Vec<u8>> {
    let key = public_key(target)?;
    let rsa = key.rsa()?;
    let n = biguint(rsa.n());
    let e = biguint(rsa.e());
    ensure!(
        *p > BigUint::one() && *q > BigUint::one() && p != q && p * q == n,
        "invalid factorization for semiprime RSA"
    );
    let pm = p - 1u8;
    let qm = q - 1u8;
    let lambda = pm.lcm(&qm);
    let d = inverse(&e, &lambda).ok_or_else(|| anyhow::anyhow!("RSA exponent not invertible"))?;
    let iqmp = inverse(q, p).ok_or_else(|| anyhow::anyhow!("RSA factors not coprime"))?;
    let rsa = Rsa::from_private_components(
        bignum(&n)?,
        bignum(&e)?,
        bignum(&d)?,
        bignum(p)?,
        bignum(q)?,
        bignum(&(&d % &pm))?,
        bignum(&(&d % &qm))?,
        bignum(&iqmp)?,
    )?;
    ensure!(
        rsa.check_key()?,
        "reconstructed RSA key rejected by backend"
    );
    let private = PKey::from_rsa(rsa)?;
    let pem = private.private_key_to_pem_pkcs8()?;
    verify_private(target, &pem)?;
    let message = BigUint::from(42u8) % &n;
    ensure!(
        message.modpow(&e, &n).modpow(&d, &n) == message,
        "RSA modular round-trip failed"
    );
    // Tiny laboratory moduli cannot encode a SHA-256 PKCS#1 signature.
    if key.bits() < 1024 {
        return Ok(pem);
    }
    // Verify an actual signature round trip, independently of factor matching.
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &private)?;
    signer.update(b"cert-cracker RSA recovery verification v1")?;
    let signature = signer.sign_to_vec()?;
    let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &key)?;
    verifier.update(b"cert-cracker RSA recovery verification v1")?;
    ensure!(
        verifier.verify(&signature)?,
        "RSA signature round-trip failed"
    );
    Ok(pem)
}

pub fn wiener(n: &BigUint, e: &BigUint) -> Option<(BigUint, BigUint)> {
    let (mut a, mut b) = (e.clone(), n.clone());
    let (mut h0, mut h1) = (BigUint::zero(), BigUint::one());
    let (mut k0, mut k1) = (BigUint::one(), BigUint::zero());
    while !b.is_zero() {
        let (quotient, remainder) = a.div_rem(&b);
        a = b;
        b = remainder;
        let h = &quotient * &h1 + &h0;
        let k = &quotient * &k1 + &k0;
        h0 = h1;
        h1 = h.clone();
        k0 = k1;
        k1 = k.clone();
        if h.is_zero() || k.is_zero() {
            continue;
        }
        let ed = e * &k;
        if ed <= BigUint::one() {
            continue;
        }
        let ed1 = ed - 1u8;
        if &ed1 % &h != BigUint::zero() {
            continue;
        }
        let phi = ed1 / &h;
        if phi > n + 1u8 {
            continue;
        }
        let s = n + 1u8 - phi;
        let s2 = &s * &s;
        let four_n = n * 4u8;
        if s2 < four_n {
            continue;
        }
        let delta = s2 - four_n;
        let root = delta.sqrt();
        if &root * &root != delta || (&s + &root).is_odd() {
            continue;
        }
        let p = (&s + &root) / 2u8;
        if p > BigUint::one() && n % &p == BigUint::zero() {
            let q = n / &p;
            if p != q {
                return Some((p, q));
            }
        }
    }
    None
}

pub fn fermat(n: &BigUint, steps: u64) -> Option<(BigUint, BigUint)> {
    if n.is_even() {
        return if *n > BigUint::from(2u8) {
            Some((2u8.into(), n / 2u8))
        } else {
            None
        };
    }
    let mut a = n.sqrt();
    if &a * &a < *n {
        a += 1u8;
    }
    for _ in 0..steps {
        let b2 = &a * &a - n;
        let b = b2.sqrt();
        if &b * &b == b2 {
            let p = &a - &b;
            let q = &a + &b;
            if p > BigUint::one() && p != q {
                return Some((p, q));
            }
        }
        a += 1u8;
    }
    None
}

fn trial(n: &BigUint, limit: u64) -> Option<(BigUint, BigUint)> {
    if n.is_even() && *n > BigUint::from(2u8) {
        return Some((2u8.into(), n / 2u8));
    }
    for candidate in (3..=limit).step_by(2) {
        let p = BigUint::from(candidate);
        if &p * &p > *n {
            break;
        }
        if n % &p == BigUint::zero() {
            return Some((p.clone(), n / p));
        }
    }
    None
}

pub fn analyze(targets: &[Target], trial_limit: u64, fermat_steps: u64) -> Result<Vec<Analysis>> {
    ensure!(
        trial_limit <= 1_000_000 && fermat_steps <= 1_000_000,
        "audit budgets must be <=1000000; use a specialized engine for larger jobs"
    );
    ensure!(
        targets.len() <= 4096,
        "reference pairwise shared-prime audit is limited to 4096 targets"
    );
    let mut rsa = vec![];
    for t in targets {
        let key = public_key(t)?;
        if key.id() == Id::RSA {
            let r = key.rsa()?;
            rsa.push((t.id.clone(), biguint(r.n()), biguint(r.e())));
        }
    }
    let mut result = vec![];
    for t in targets {
        let Some((_, n, e)) = rsa.iter().find(|r| r.0 == t.id) else {
            result.push(Analysis {
                target_id: t.id.clone(),
                algorithm: t.algorithm.clone(),
                checks: vec![],
                outcome: "unsupported_by_rsa_audit".into(),
                method: None,
                finding_id: None,
                private_pem: None,
            });
            continue;
        };
        let mut checks = vec!["pairwise_shared_prime".to_owned()];
        let mut candidate = None;
        for (id, other, _) in &rsa {
            if *id == t.id {
                continue;
            }
            if n == other {
                checks.push("shared_modulus_requires_additional_evidence".into());
                continue;
            }
            let g = n.gcd(other);
            if g == *n {
                checks.push("full_modulus_gcd_requires_further_factor_analysis".into());
            }
            if g > BigUint::one() && g < *n {
                candidate = Some(("shared_prime", g.clone(), n / &g));
                break;
            }
        }
        if candidate.is_none() {
            checks.push("wiener".into());
            candidate = wiener(n, e).map(|(p, q)| ("wiener", p, q));
        }
        if candidate.is_none() && trial_limit > 0 {
            checks.push(format!("trial_division_limit_{trial_limit}"));
            candidate = trial(n, trial_limit).map(|(p, q)| ("trial_division", p, q));
        }
        if candidate.is_none() && fermat_steps > 0 {
            checks.push(format!("fermat_iterations_{fermat_steps}"));
            candidate = fermat(n, fermat_steps).map(|(p, q)| ("fermat", p, q));
        }
        let (outcome, method, private_pem) = if let Some((method, p, q)) = candidate {
            match rsa_private(t, &p, &q) {
                Ok(pem) => ("verified_recovery", Some(method.into()), Some(pem)),
                Err(_) => (
                    "factor_found_but_private_key_reconstruction_unsupported",
                    Some(method.into()),
                    None,
                ),
            }
        } else {
            ("no_weakness_detected_by_completed_checks", None, None)
        };
        result.push(Analysis {
            target_id: t.id.clone(),
            algorithm: t.algorithm.clone(),
            checks,
            outcome: outcome.into(),
            method,
            finding_id: None,
            private_pem,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_fermat_and_wiener() {
        assert_eq!(
            fermat(&BigUint::from(1009u64 * 1013), 1),
            Some((1009u32.into(), 1013u32.into()))
        );
        assert!(fermat(&BigUint::from(101u32 * 1009), 0).is_none());
        let n = BigUint::from(1009u32 * 1013);
        let e = inverse(&BigUint::from(5u8), &BigUint::from(1008u32 * 1012)).unwrap();
        let (p, q) = wiener(&n, &e).unwrap();
        assert_eq!(p * q, n);
    }
}
