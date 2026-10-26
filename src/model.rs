use anyhow::{Result, bail, ensure};
use num_bigint::BigUint;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ENGINE_VERSION: u32 = 1;

pub fn number(value: &str) -> Result<BigUint> {
    let (digits, radix) = value.strip_prefix("0x").map_or((value, 10), |v| (v, 16));
    ensure!(!digits.is_empty(), "empty integer");
    ensure!(
        digits.bytes().all(|b| if radix == 16 {
            b.is_ascii_hexdigit()
        } else {
            b.is_ascii_digit()
        }),
        "invalid unsigned integer: {value}"
    );
    BigUint::parse_bytes(digits.as_bytes(), radix).ok_or_else(|| anyhow::anyhow!("invalid integer"))
}

pub fn canonical(n: &BigUint) -> String {
    format!("0x{}", n.to_str_radix(16))
}
pub fn fingerprint(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub sha256: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub issuer_signature_algorithm: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    pub id: String,
    pub algorithm: String,
    pub bits: u32,
    pub curve: Option<String>,
    pub public_key_der: String,
    pub spki_sha256: String,
    pub sources: Vec<String>,
    pub certificates: Vec<CertificateInfo>,
    pub validation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchSpec {
    pub engine_version: u32,
    pub target_id: String,
    pub method: String,
    pub start: String,
    pub end: String,
    pub chunk_size: u64,
    // Omitted for old sequential jobs so their existing specification hashes remain valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bsgs: Option<BsgsConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BsgsConfig {
    pub baby_steps: u64,
    pub memory_budget_bytes: u64,
    pub table_format_version: u32,
}

impl SearchSpec {
    pub fn sequential(target_id: String, start: &str, end: &str, chunk_size: u64) -> Result<Self> {
        let a = number(start)?;
        let b = number(end)?;
        ensure!(
            !a.is_zero() && a < b,
            "range must satisfy 1 <= start < end (end is exclusive)"
        );
        ensure!(
            (1..=10_000_000).contains(&chunk_size),
            "chunk size must be between 1 and 10000000"
        );
        Ok(Self {
            engine_version: ENGINE_VERSION,
            target_id,
            method: "ec-sequential".into(),
            start: canonical(&a),
            end: canonical(&b),
            chunk_size,
            bsgs: None,
        })
    }
    pub fn bsgs(
        target_id: String,
        start: &str,
        end: &str,
        chunk_size: u64,
        config: BsgsConfig,
    ) -> Result<Self> {
        let mut spec = Self::sequential(target_id, start, end, chunk_size)?;
        spec.method = "ec-bsgs".into();
        spec.bsgs = Some(config);
        spec.validate()?;
        Ok(spec)
    }
    pub fn work_bounds(&self) -> Result<(BigUint, BigUint)> {
        let start = number(&self.start)?;
        let end = number(&self.end)?;
        if let Some(config) = &self.bsgs {
            let m = BigUint::from(config.baby_steps);
            ensure!(!m.is_zero(), "zero baby-step count");
            Ok((BigUint::zero(), (&end - &start + &m - 1u8) / m))
        } else {
            Ok((start, end))
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.engine_version == ENGINE_VERSION,
            "incompatible engine version"
        );
        ensure!(
            matches!(self.method.as_str(), "ec-sequential" | "ec-bsgs"),
            "unsupported checkpoint engine: {}",
            self.method
        );
        let mut normalized = Self::sequential(
            self.target_id.clone(),
            &self.start,
            &self.end,
            self.chunk_size,
        )?;
        if self.method == "ec-bsgs" {
            let config = self
                .bsgs
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing BSGS parameters"))?;
            ensure!(
                config.table_format_version == 1,
                "incompatible BSGS table format"
            );
            ensure!(
                config.baby_steps > 0
                    && BigUint::from(config.baby_steps)
                        <= number(&self.end)? - number(&self.start)?,
                "invalid baby-step count"
            );
            ensure!(
                (1_048_576..=68_719_476_736).contains(&config.memory_budget_bytes),
                "BSGS memory budget must be 1 MiB..64 GiB"
            );
            normalized.method = self.method.clone();
            normalized.bsgs = self.bsgs.clone();
        }
        ensure!(*self == normalized, "noncanonical search specification");
        Ok(())
    }
    pub fn hash(&self) -> Result<String> {
        Ok(fingerprint(&serde_json::to_vec(self)?))
    }
}

#[derive(Clone, Debug)]
pub struct WorkUnit {
    pub id: i64,
    pub generation: i64,
    pub start: BigUint,
    pub end: BigUint,
    pub next: BigUint,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Coverage {
    pub start: String,
    pub end: String,
}

pub fn merged_coverage(mut spans: Vec<(BigUint, BigUint)>) -> Result<Vec<Coverage>> {
    spans.sort();
    let mut merged: Vec<(BigUint, BigUint)> = vec![];
    for (a, b) in spans {
        if a > b {
            bail!("invalid stored coverage")
        }
        if a == b {
            continue;
        }
        if let Some(last) = merged.last_mut()
            && a <= last.1
        {
            last.1 = last.1.clone().max(b);
            continue;
        }
        merged.push((a, b));
    }
    Ok(merged
        .into_iter()
        .map(|(a, b)| Coverage {
            start: canonical(&a),
            end: canonical(&b),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_large_bounds_and_rejected_inputs() {
        let n = (BigUint::from(1u8) << 520usize) + BigUint::from(17u8);
        assert_eq!(number(&canonical(&n)).unwrap(), n);
        for invalid in ["", "0x", "-1", "+2", " 4", "1.2", "0xzz"] {
            assert!(number(invalid).is_err());
        }
    }
    #[test]
    fn coverage_does_not_fill_gaps() {
        let spans = vec![(1u8, 4u8), (8, 11), (3, 6), (11, 12)];
        let merged = merged_coverage(
            spans
                .into_iter()
                .map(|(a, b)| (a.into(), b.into()))
                .collect(),
        )
        .unwrap();
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].end, "0x6");
        assert_eq!(merged[1].start, "0x8");
    }
}
