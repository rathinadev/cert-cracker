use crate::{
    crypto::ec_order,
    model::{BsgsConfig, SearchSpec, Target, number},
};
use anyhow::{Result, ensure};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde_json::{Value, json};

pub const BASE_WORKSPACE: u64 = 2 * 1024 * 1024;
pub const WORKER_WORKSPACE: u64 = 512 * 1024;
pub const MAX_POINT_BYTES: usize = 67;

#[derive(Clone, Debug)]
pub struct Entry {
    pub point: [u8; MAX_POINT_BYTES],
    pub index: u64,
}

pub fn memory_required(entries: u64, workers: usize) -> Result<u64> {
    let bytes = (entries as u128) * (std::mem::size_of::<Entry>() as u128)
        + (entries as u128).div_ceil(8)
        + u128::from(BASE_WORKSPACE)
        + (workers as u128) * u128::from(WORKER_WORKSPACE);
    u64::try_from(bytes).map_err(Into::into)
}

pub fn preflight(spec: &SearchSpec, workers: usize) -> Result<()> {
    ensure!((1..=256).contains(&workers), "worker count must be 1..256");
    if let Some(c) = &spec.bsgs {
        ensure!(
            memory_required(c.baby_steps, workers)? <= c.memory_budget_bytes,
            "BSGS table/workspace exceeds the job's memory budget with {workers} workers; reduce workers or create a new plan with a larger budget"
        );
    }
    Ok(())
}

pub fn ensure_curve(target: &Target) -> Result<()> {
    ensure!(
        matches!(
            target.curve.as_deref(),
            Some("prime256v1" | "secp384r1" | "secp521r1" | "secp256k1")
        ),
        "BSGS is enabled for P-256, P-384, P-521 and secp256k1 only"
    );
    Ok(())
}

#[derive(Clone, Copy)]
pub struct PlanOptions<'a> {
    pub start: &'a str,
    pub end: &'a str,
    pub chunk_size: u64,
    pub method: &'a str,
    pub memory_mib: u64,
    pub baby_steps: Option<u64>,
    pub workers: usize,
}

pub fn plan(target: &Target, options: PlanOptions<'_>) -> Result<(SearchSpec, Value)> {
    let PlanOptions {
        start,
        end,
        chunk_size: chunk,
        method,
        memory_mib,
        baby_steps,
        workers,
    } = options;
    ensure!((1..=256).contains(&workers), "worker count must be 1..256");
    ensure!(
        matches!(method, "auto" | "sequential" | "bsgs"),
        "method must be auto, sequential or bsgs"
    );
    let sequential = SearchSpec::sequential(target.id.clone(), start, end, chunk)?;
    let a = number(&sequential.start)?;
    let b = number(&sequential.end)?;
    ensure!(
        b <= ec_order(target)?,
        "exclusive end exceeds curve subgroup order"
    );
    let width = &b - &a;
    let mut recommendation = "sequential";
    let mut alternative = None;
    let mut reason = "Sequential search avoids table setup for this interval".to_owned();
    let mut bsgs_spec = None;
    let memory = memory_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("memory budget overflow"))?;
    ensure!(
        (1..=65536).contains(&memory_mib),
        "memory budget must be 1..65536 MiB"
    );
    let reserved = BASE_WORKSPACE + workers as u64 * WORKER_WORKSPACE;
    let max_entries = memory.saturating_sub(reserved) as u128 * 8
        / (std::mem::size_of::<Entry>() as u128 * 8 + 1);
    if ensure_curve(target).is_ok() && max_entries > 0 {
        let mut root = width.sqrt();
        if &root * &root < width {
            root += 1u8;
        }
        let count =
            baby_steps.unwrap_or_else(|| root.to_u64().unwrap_or(u64::MAX).min(max_entries as u64));
        ensure!(
            count > 0 && count as u128 <= max_entries && BigUint::from(count) <= width,
            "baby-step count does not fit interval or memory budget"
        );
        let m = BigUint::from(count);
        let giants = (&width + &m - 1u8) / &m;
        let operations = &m + &giants;
        if width > BigUint::from(4096u32) && &operations * 16u8 < width {
            recommendation = "bsgs";
            reason="BSGS has lower estimated work after a conservative 16x per-step setup/serialization allowance; this is an operation model, not a measured runtime prediction".into();
        }
        alternative = Some(
            json!({"baby_steps":count,"giant_steps":giants.to_str_radix(10),"estimated_group_steps":operations.to_str_radix(10),"resident_entry_bytes":std::mem::size_of::<Entry>(),"estimated_table_workspace_bytes":memory_required(count,workers)?,"estimated_peak_artifact_bytes":count*(MAX_POINT_BYTES as u64+8)*2+8192,"memory_budget_bytes":memory,"memory_scope":"table, validation bitmap and reserved worker buffers; allocator/OpenSSL/runtime baseline RSS is excluded","balanced_sqrt_table":count==root.to_u64().unwrap_or(u64::MAX)}),
        );
        let scheduled_chunk = chunk.min(
            ((&giants + BigUint::from(workers * 4) - 1u8) / BigUint::from(workers * 4))
                .to_u64()
                .unwrap_or(u64::MAX)
                .max(1),
        );
        bsgs_spec = Some(SearchSpec::bsgs(
            target.id.clone(),
            start,
            end,
            scheduled_chunk,
            BsgsConfig {
                baby_steps: count,
                memory_budget_bytes: memory,
                table_format_version: 1,
            },
        )?);
    } else if method == "bsgs" {
        ensure_curve(target)?;
        anyhow::bail!("memory budget is too small for BSGS workspace and {workers} workers");
    } else {
        ensure!(
            baby_steps.is_none(),
            "baby-step override requires an available BSGS plan"
        );
    }
    let selected = if method == "auto" {
        recommendation
    } else {
        method
    };
    let spec = if selected == "bsgs" {
        bsgs_spec.ok_or_else(|| anyhow::anyhow!("BSGS unavailable for this target/budget"))?
    } else {
        ensure!(
            baby_steps.is_none(),
            "baby-step override is incompatible with sequential search"
        );
        sequential
    };
    preflight(&spec, workers)?;
    let estimate = json!({"requested_method":method,"selected_method":spec.method,"recommendation":recommendation,"reason":reason,"interval_candidates":width.to_str_radix(10),"sequential_group_comparisons":width.to_str_radix(10),"bsgs":alternative,"workers":workers,"estimated_seconds":null,"timing_note":"No calibrated cross-algorithm ETA is available; group-step counts are estimates","unavailable_alternative":"Pollard kangaroo is not implemented; a smaller table trades memory for more giant steps"});
    Ok((spec, estimate))
}
