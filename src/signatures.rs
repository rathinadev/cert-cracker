//! ECDSA repeated-nonce analysis over verified, explicitly supplied digests.
use crate::{crypto, import, model::Target};
use anyhow::{Context, Result, ensure};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use openssl::ecdsa::EcdsaSig;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dataset {
    pub signatures: Vec<Signature>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Exact message digest bytes used by the signer, not the unhashed message.
    pub digest_hex: String,
    /// DER-encoded ECDSA signature (r,s).
    pub signature_der_hex: String,
}
#[derive(Serialize)]
pub struct SignatureAudit {
    pub target_id: String,
    pub verified_signatures: usize,
    pub distinct_effective_signatures: usize,
    pub repeated_r_groups: usize,
    pub pairs_checked: usize,
    pub outcome: &'static str,
    pub finding_id: Option<i64>,
    #[serde(skip)]
    pub private_pem: Option<Vec<u8>>,
}

pub fn load(path: &Path) -> Result<Dataset> {
    let file = std::fs::File::open(path).context("opening signature dataset")?;
    ensure!(
        file.metadata()?.is_file(),
        "signature dataset must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "signature dataset exceeds 4 MiB"
    );
    let data: Dataset = serde_json::from_slice(&bytes).context("invalid signature dataset")?;
    ensure!(
        (1..=1024).contains(&data.signatures.len()),
        "signature dataset must contain 1..1024 entries"
    );
    Ok(data)
}

fn inverse(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    let g = a.to_bigint()?.extended_gcd(&n.to_bigint()?);
    if g.gcd != BigInt::one() {
        return None;
    }
    g.x.mod_floor(&n.to_bigint()?).to_biguint()
}

pub fn audit(target: &Target, data: &Dataset) -> Result<SignatureAudit> {
    ensure!(
        (1..=1024).contains(&data.signatures.len()),
        "signature dataset must contain 1..1024 entries"
    );
    let order = crypto::ec_order(target)?;
    let key = import::public_key(target)?.ec_key()?;
    let mut groups: BTreeMap<BigUint, Vec<(BigUint, BigUint)>> = BTreeMap::new();
    for (index, entry) in data.signatures.iter().enumerate() {
        ensure!(
            !entry.digest_hex.is_empty()
                && entry.digest_hex.len() <= 128
                && entry.signature_der_hex.len() <= 300,
            "invalid signature or digest length at entry {index}"
        );
        let digest = hex::decode(&entry.digest_hex)
            .with_context(|| format!("invalid digest at entry {index}"))?;
        let der = hex::decode(&entry.signature_der_hex)
            .with_context(|| format!("invalid DER hex at entry {index}"))?;
        let signature = EcdsaSig::from_der(&der)
            .with_context(|| format!("invalid DER signature at entry {index}"))?;
        ensure!(
            signature.to_der()? == der,
            "noncanonical DER signature at entry {index}"
        );
        ensure!(
            signature.verify(&digest, &key)?,
            "signature {index} does not verify against this signer and digest"
        );
        let r = crypto::biguint(signature.r());
        let s = crypto::biguint(signature.s());
        ensure!(
            !r.is_zero() && r < order && !s.is_zero() && s < order,
            "invalid signature scalars at entry {index}"
        );
        let mut z = BigUint::from_bytes_be(&digest);
        let bits = digest.len() as u64 * 8;
        if bits > order.bits() {
            z >>= (bits - order.bits()) as usize;
        }
        z %= &order;
        let bucket = groups.entry(r).or_default();
        if !bucket.contains(&(z.clone(), s.clone())) {
            bucket.push((z, s));
        }
    }
    let distinct = groups.values().map(Vec::len).sum();
    let repeated = groups.values().filter(|v| v.len() > 1).count();
    let distinct_digests: std::collections::BTreeSet<_> = groups
        .values()
        .flat_map(|bucket| bucket.iter().map(|(z, _)| z))
        .collect();
    let mut report = SignatureAudit {
        target_id: target.id.clone(),
        verified_signatures: data.signatures.len(),
        distinct_effective_signatures: distinct,
        repeated_r_groups: repeated,
        pairs_checked: 0,
        outcome: if distinct_digests.len() < 2 {
            "insufficient_distinct_evidence"
        } else {
            "no_verified_recovery"
        },
        finding_id: None,
        private_pem: None,
    };
    for (r, bucket) in groups {
        for i in 0..bucket.len() {
            for j in i + 1..bucket.len() {
                let (z1, s1) = &bucket[i];
                let (z2, s2) = &bucket[j];
                if z1 == z2 {
                    continue;
                }
                if report.pairs_checked >= 4096 {
                    report.outcome = "pair_limit_reached";
                    return Ok(report);
                }
                report.pairs_checked += 1;
                let Some(r_inv) = inverse(&r, &order) else {
                    continue;
                };
                for s2_candidate in [s2.clone(), &order - s2] {
                    let denominator = (s1 + &order - s2_candidate) % &order;
                    let Some(inv) = inverse(&denominator, &order) else {
                        continue;
                    };
                    let nonce = ((z1 + &order - z2) * inv) % &order;
                    let d = (((s1 * nonce) % &order + &order - z1) * &r_inv) % &order;
                    if let Ok(pem) = crypto::recover_ec(target, &d) {
                        report.outcome = "verified_recovery";
                        report.private_pem = Some(pem);
                        return Ok(report);
                    }
                }
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        bn::{BigNum, BigNumContext},
        ec::EcPoint,
        pkey::PKey,
    };
    fn fixture(digest: &[u8], secret: u32, nonce: u32, flip: bool) -> (Target, Signature) {
        let d = BigUint::from(secret);
        let k = BigUint::from(nonce);
        let private = crypto::lab_key("P-256", &d).unwrap();
        let public = PKey::public_key_from_der(&private.public_key_to_der().unwrap()).unwrap();
        let target = import::target_from_key(&public, "fixture").unwrap();
        let order = crypto::ec_order(&target).unwrap();
        let key = public.ec_key().unwrap();
        let group = key.group();
        let mut ctx = BigNumContext::new().unwrap();
        let mut point = EcPoint::new(group).unwrap();
        point
            .mul_generator2(group, &crypto::bignum(&k).unwrap(), &mut ctx)
            .unwrap();
        let (mut x, mut y) = (BigNum::new().unwrap(), BigNum::new().unwrap());
        point
            .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)
            .unwrap();
        let r = crypto::biguint(&x) % &order;
        let z = BigUint::from_bytes_be(digest) % &order;
        let mut s = (inverse(&k, &order).unwrap() * (z + &r * d)) % &order;
        if flip {
            s = &order - s;
        }
        let sig = EcdsaSig::from_private_components(
            crypto::bignum(&r).unwrap(),
            crypto::bignum(&s).unwrap(),
        )
        .unwrap();
        (
            target,
            Signature {
                digest_hex: hex::encode(digest),
                signature_der_hex: hex::encode(sig.to_der().unwrap()),
            },
        )
    }
    #[test]
    fn verifies_and_recovers_repeated_nonce_including_flipped_s() {
        let (target, a) = fixture(&[1; 32], 42, 17, false);
        let (_, b) = fixture(&[2; 32], 42, 17, true);
        let result = audit(
            &target,
            &Dataset {
                signatures: vec![a, b],
            },
        )
        .unwrap();
        assert_eq!(result.outcome, "verified_recovery");
        crypto::verify_private(&target, result.private_pem.as_ref().unwrap()).unwrap();
    }
    #[test]
    fn duplicate_and_wrong_signer_are_not_claimed_as_recovery() {
        let (target, a) = fixture(&[1; 32], 42, 17, false);
        let (_, duplicate) = fixture(&[1; 32], 42, 17, false);
        let result = audit(
            &target,
            &Dataset {
                signatures: vec![a, duplicate],
            },
        )
        .unwrap();
        assert_eq!(result.outcome, "insufficient_distinct_evidence");
        let (_, a) = fixture(&[1; 32], 42, 17, false);
        let (_, opposite) = fixture(&[1; 32], 42, 17, true);
        let result = audit(
            &target,
            &Dataset {
                signatures: vec![a, opposite],
            },
        )
        .unwrap();
        assert_eq!(result.outcome, "insufficient_distinct_evidence");
        let (_, wrong) = fixture(&[2; 32], 43, 17, false);
        assert!(
            audit(
                &target,
                &Dataset {
                    signatures: vec![wrong]
                }
            )
            .err()
            .unwrap()
            .to_string()
            .contains("does not verify")
        );
    }
}
