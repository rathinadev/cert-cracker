use crate::{
    import::{public_key, target_from_key},
    model::{Target, WorkUnit, canonical},
};
use anyhow::{Context, Result, ensure};
use num_bigint::BigUint;
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private},
    x509::{X509, X509NameBuilder},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub fn bignum(value: &BigUint) -> Result<BigNum> {
    Ok(BigNum::from_slice(&value.to_bytes_be())?)
}
pub fn biguint(value: &openssl::bn::BigNumRef) -> BigUint {
    BigUint::from_bytes_be(&value.to_vec())
}

pub fn ec_order(target: &Target) -> Result<BigUint> {
    let key = public_key(target)?;
    ensure!(
        key.id() == Id::EC,
        "EC search requires an EC subject key; {} recovery is unsupported by this engine",
        target.algorithm
    );
    let ec = key.ec_key()?;
    ensure!(
        ec.group().curve_name().is_some(),
        "explicit/unnamed EC groups are not enabled for search"
    );
    ec.check_key()?;
    let mut order = BigNum::new()?;
    let mut ctx = BigNumContext::new()?;
    ec.group().order(&mut order, &mut ctx)?;
    Ok(biguint(&order))
}

pub struct EcWorker {
    group: EcGroup,
    target: EcPoint,
    ctx: BigNumContext,
}

impl EcWorker {
    pub fn new(target: &Target) -> Result<Self> {
        ec_order(target)?;
        let key = public_key(target)?;
        let ec = key.ec_key()?;
        let group = EcGroup::from_curve_name(ec.group().curve_name().context("missing curve")?)?;
        let mut ctx = BigNumContext::new()?;
        let bytes = ec.public_key().to_bytes(
            ec.group(),
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )?;
        let point = EcPoint::from_bytes(&group, &bytes, &mut ctx)?;
        Ok(Self {
            group,
            target: point,
            ctx,
        })
    }

    /// Progress is the next untested scalar. An uncommitted tail can safely replay.
    pub fn search(
        &mut self,
        unit: &WorkUnit,
        cancel: &Arc<AtomicBool>,
        checkpoint_every: Duration,
        mut progress: impl FnMut(&BigUint) -> Result<()>,
    ) -> Result<(BigUint, Option<BigUint>)> {
        let mut next = unit.next.clone();
        let mut point = EcPoint::new(&self.group)?;
        let first = bignum(&next)?;
        point.mul_generator2(&self.group, &first, &mut self.ctx)?;
        let mut scratch = EcPoint::new(&self.group)?;
        let mut checked = 0u32;
        let mut checkpoint = Instant::now();
        while next < unit.end {
            if checked.is_multiple_of(128) {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                if checkpoint.elapsed() >= checkpoint_every {
                    progress(&next)?;
                    checkpoint = Instant::now();
                }
            }
            let matched = point.eq(&self.group, &self.target, &mut self.ctx)?;
            if matched {
                let candidate = next.clone();
                next += 1u8;
                return Ok((next, Some(candidate)));
            }
            next += 1u8;
            scratch.add(
                &self.group,
                &point,
                self.group
                    .generator_opt()
                    .context("group has no generator")?,
                &mut self.ctx,
            )?;
            std::mem::swap(&mut point, &mut scratch);
            checked = checked.wrapping_add(1);
        }
        Ok((next, None))
    }
}

pub fn recover_ec(target: &Target, scalar: &BigUint) -> Result<Vec<u8>> {
    ensure!(
        *scalar > BigUint::from(0u8) && *scalar < ec_order(target)?,
        "candidate is outside scalar domain"
    );
    let key = public_key(target)?;
    let ec = key.ec_key()?;
    let group = ec.group();
    let mut ctx = BigNumContext::new()?;
    let secret = bignum(scalar)?;
    let mut point = EcPoint::new(group)?;
    // This full multiplication is independent of the worker's incremental point path.
    point.mul_generator2(group, &secret, &mut ctx)?;
    ensure!(
        point.eq(group, ec.public_key(), &mut ctx)?,
        "candidate verification failed"
    );
    let private = EcKey::from_private_components(group, &secret, &point)?;
    private.check_key()?;
    let private = PKey::from_ec_key(private)?;
    verify_private(target, &private.private_key_to_pem_pkcs8()?)?;
    Ok(private.private_key_to_pem_pkcs8()?)
}

pub fn verify_private(target: &Target, pem: &[u8]) -> Result<()> {
    let private = PKey::private_key_from_pem(pem)?;
    let public = PKey::public_key_from_der(&private.public_key_to_der()?)?;
    ensure!(
        target_from_key(&public, "")?.id == target.id,
        "recovered private key does not match target"
    );
    if private.id() == Id::EC {
        private.ec_key()?.check_key()?;
    }
    if private.id() == Id::RSA {
        ensure!(
            private.rsa()?.check_key()?,
            "invalid RSA private components"
        );
    }
    Ok(())
}

pub fn curve_nid(name: &str) -> Result<Nid> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "p-256" | "p256" | "prime256v1" | "secp256r1" => Nid::X9_62_PRIME256V1,
        "p-384" | "p384" | "secp384r1" => Nid::SECP384R1,
        "p-521" | "p521" | "secp521r1" => Nid::SECP521R1,
        "secp256k1" => Nid::SECP256K1,
        _ => anyhow::bail!("lab curve must be P-256, P-384, P-521 or secp256k1"),
    })
}

pub fn lab_key(curve: &str, scalar: &BigUint) -> Result<PKey<Private>> {
    let group = EcGroup::from_curve_name(curve_nid(curve)?)?;
    let mut ctx = BigNumContext::new()?;
    let mut order = BigNum::new()?;
    group.order(&mut order, &mut ctx)?;
    ensure!(
        *scalar > BigUint::from(0u8) && *scalar < biguint(&order),
        "lab scalar outside curve order"
    );
    let secret = bignum(scalar)?;
    let mut point = EcPoint::new(&group)?;
    point.mul_generator2(&group, &secret, &mut ctx)?;
    Ok(PKey::from_ec_key(EcKey::from_private_components(
        &group, &secret, &point,
    )?)?)
}

pub fn lab_certificate(curve: &str, scalar: &BigUint) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = lab_key(curve, scalar)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text(
        "CN",
        "cert-cracker deliberately weak laboratory certificate",
    )?;
    let name = name.build();
    let mut cert = X509::builder()?;
    cert.set_version(2)?;
    let serial = BigNum::from_u32(1)?.to_asn1_integer()?;
    cert.set_serial_number(&serial)?;
    cert.set_subject_name(&name)?;
    cert.set_issuer_name(&name)?;
    cert.set_pubkey(&key)?;
    let before = Asn1Time::days_from_now(0)?;
    let after = Asn1Time::days_from_now(7)?;
    cert.set_not_before(&before)?;
    cert.set_not_after(&after)?;
    cert.sign(&key, MessageDigest::sha256())?;
    Ok((cert.build().to_pem()?, key.public_key_to_pem()?))
}

pub fn scalar_note(value: &BigUint) -> String {
    canonical(value)
}
