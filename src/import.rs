use crate::model::{CertificateInfo, Target, fingerprint};
use anyhow::{Context, Result, bail, ensure};
use openssl::{
    bn::BigNumContext,
    ec::PointConversionForm,
    pkey::{Id, PKey, Public},
    rsa::Rsa,
    x509::X509,
};
use std::{collections::BTreeMap, fs::File, io::Read, path::Path};

const MAX_BYTES: u64 = 16 * 1024 * 1024;

fn exact_der(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() >= 2 && bytes[0] == 0x30,
        "expected DER SEQUENCE"
    );
    let (header, length) = if bytes[1] & 0x80 == 0 {
        (2, usize::from(bytes[1]))
    } else {
        let count = usize::from(bytes[1] & 0x7f);
        ensure!(
            count > 0 && count <= std::mem::size_of::<usize>() && bytes.len() >= 2 + count,
            "invalid DER length"
        );
        let mut length = 0usize;
        for &b in &bytes[2..2 + count] {
            length = length
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(b)))
                .context("DER length overflow")?;
        }
        ensure!(length >= 128 && bytes[2] != 0, "noncanonical DER length");
        (2 + count, length)
    };
    ensure!(
        header.checked_add(length) == Some(bytes.len()),
        "trailing bytes or truncated DER object"
    );
    Ok(())
}

pub fn target_from_key(key: &PKey<Public>, source: &str) -> Result<Target> {
    let der = key.public_key_to_der()?;
    let mut curve = None;
    let (algorithm, identity, validation) = match key.id() {
        Id::EC => {
            let ec = key.ec_key()?;
            ec.check_key().context("invalid EC public key")?;
            let mut ctx = BigNumContext::new()?;
            let point = ec.public_key().to_bytes(
                ec.group(),
                PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )?;
            let name = ec
                .group()
                .curve_name()
                .map(|n| n.short_name().unwrap_or("unknown").to_owned());
            curve = name.clone();
            let identity = if let Some(name) = name {
                format!("EC:{name}:{}", hex::encode(point))
            } else {
                format!("EC-EXPLICIT:{}", hex::encode(&der))
            };
            (
                "EC".to_owned(),
                identity,
                "EC public key validated; certificate trust not evaluated".to_owned(),
            )
        }
        Id::RSA | Id::RSA_PSS => {
            let rsa = key.rsa()?;
            ensure!(
                rsa.n().num_bits() > 1 && rsa.e().num_bits() > 0,
                "invalid RSA public parameters"
            );
            (
                if key.id() == Id::RSA_PSS {
                    "RSA-PSS"
                } else {
                    "RSA"
                }
                .to_owned(),
                format!("RSA:{}:{}", rsa.n().to_hex_str()?, rsa.e().to_hex_str()?),
                "RSA parameters parsed; private-key consistency and trust not evaluated".to_owned(),
            )
        }
        Id::ED25519 => (
            "Ed25519".into(),
            format!("Ed25519:{}", hex::encode(key.raw_public_key()?)),
            "Public key parsed; recovery engine unavailable".into(),
        ),
        Id::ED448 => (
            "Ed448".into(),
            format!("Ed448:{}", hex::encode(key.raw_public_key()?)),
            "Public key parsed; recovery engine unavailable".into(),
        ),
        Id::X25519 => (
            "X25519".into(),
            format!("X25519:{}", hex::encode(key.raw_public_key()?)),
            "Key-agreement public key parsed; recovery engine unavailable".into(),
        ),
        Id::X448 => (
            "X448".into(),
            format!("X448:{}", hex::encode(key.raw_public_key()?)),
            "Key-agreement public key parsed; recovery engine unavailable".into(),
        ),
        Id::DSA => (
            "DSA".into(),
            format!("DSA:{}", hex::encode(&der)),
            "Public key parsed; signature dataset analysis unavailable".into(),
        ),
        Id::DH => (
            "DH".into(),
            format!("DH:{}", hex::encode(&der)),
            "Key-agreement public key parsed; recovery engine unavailable".into(),
        ),
        other => (
            format!("backend-id-{}", other.as_raw()),
            hex::encode(&der),
            "Parsed by backend; analysis unsupported".into(),
        ),
    };
    Ok(Target {
        id: fingerprint(identity.as_bytes()),
        algorithm,
        bits: key.bits(),
        curve,
        spki_sha256: fingerprint(&der),
        public_key_der: hex::encode(der),
        sources: vec![source.into()],
        certificates: vec![],
        validation,
    })
}

fn certificate(cert: X509, source: &str) -> Result<Target> {
    let mut target = target_from_key(&cert.public_key()?, source)?;
    fn name(n: &openssl::x509::X509NameRef) -> String {
        n.entries()
            .map(|e| {
                format!(
                    "{}={}",
                    e.object().nid().short_name().unwrap_or("OID"),
                    e.data().to_string().unwrap_or_else(|_| "<binary>".into())
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
    target.certificates.push(CertificateInfo {
        sha256: fingerprint(&cert.to_der()?),
        subject: name(cert.subject_name()),
        issuer: name(cert.issuer_name()),
        serial: cert.serial_number().to_bn()?.to_hex_str()?.to_string(),
        not_before: cert.not_before().to_string(),
        not_after: cert.not_after().to_string(),
        issuer_signature_algorithm: cert.signature_algorithm().object().to_string(),
    });
    Ok(target)
}

pub fn load(path: &Path) -> Result<Vec<Target>> {
    let source = path.display().to_string();
    let file = File::open(path).with_context(|| format!("reading {source}"))?;
    ensure!(
        file.metadata()?.is_file(),
        "input must be a regular file: {source}"
    );
    let mut bytes = vec![];
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "input exceeds 16 MiB limit"
    );
    ensure!(!bytes.is_empty(), "empty input");
    let mut targets = vec![];
    if bytes.windows(11).any(|w| w == b"-----BEGIN ") {
        let blocks = pem::parse_many(&bytes).context("invalid PEM encoding")?;
        ensure!(
            !blocks.is_empty() && blocks.len() <= 2048,
            "PEM bundle must contain 1..2048 blocks"
        );
        for block in blocks {
            exact_der(block.contents())?;
            let t = match block.tag() {
                "CERTIFICATE" => certificate(X509::from_der(block.contents())?, &source)?,
                "PUBLIC KEY" => {
                    target_from_key(&PKey::public_key_from_der(block.contents())?, &source)?
                }
                "RSA PUBLIC KEY" => target_from_key(
                    &PKey::from_rsa(Rsa::public_key_from_der_pkcs1(block.contents())?)?,
                    &source,
                )?,
                other => bail!("unsupported PEM block {other}; supply certificates or public keys"),
            };
            targets.push(t);
        }
    } else {
        exact_der(&bytes)?;
        if let Ok(cert) = X509::from_der(&bytes) {
            targets.push(certificate(cert, &source)?);
        } else if let Ok(key) = PKey::public_key_from_der(&bytes) {
            targets.push(target_from_key(&key, &source)?);
        } else if let Ok(rsa) = Rsa::public_key_from_der_pkcs1(&bytes) {
            targets.push(target_from_key(&PKey::from_rsa(rsa)?, &source)?);
        } else {
            bail!("unsupported or malformed certificate/public key: {source}");
        }
    }
    let mut unique = BTreeMap::<String, Target>::new();
    for t in targets {
        if let Some(existing) = unique.get_mut(&t.id) {
            merge(existing, t);
        } else {
            unique.insert(t.id.clone(), t);
        }
    }
    Ok(unique.into_values().collect())
}

pub fn merge(existing: &mut Target, incoming: Target) {
    for s in incoming.sources {
        if !existing.sources.contains(&s) {
            existing.sources.push(s);
        }
    }
    for c in incoming.certificates {
        if !existing.certificates.iter().any(|v| v.sha256 == c.sha256) {
            existing.certificates.push(c);
        }
    }
}

pub fn public_key(target: &Target) -> Result<PKey<Public>> {
    let key = PKey::public_key_from_der(&hex::decode(&target.public_key_der)?)?;
    ensure!(
        target_from_key(&key, "")?.id == target.id,
        "stored target fingerprint does not match public key"
    );
    Ok(key)
}
