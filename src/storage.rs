use crate::{
    import,
    model::{SearchSpec, Target, WorkUnit, canonical, merged_coverage, number},
};
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use num_bigint::BigUint;
use num_traits::Zero;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub(crate) fn no_symlink(path: &Path) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        ensure!(
            !meta.file_type().is_symlink(),
            "refusing symlink: {}",
            path.display()
        );
    }
    Ok(())
}

pub fn private_file(path: &Path) -> Result<File> {
    no_symlink(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("creating new private file {}", path.display()))
}

pub struct Store {
    pub conn: Connection,
    _lock: Option<File>,
    pub path: PathBuf,
}

impl Store {
    pub fn open(dir: &Path, write: bool) -> Result<Self> {
        ensure!(
            rusqlite::version_number() >= 3_051_003,
            "SQLite >=3.51.3 is required for this WAL-backed implementation"
        );
        no_symlink(dir)?;
        if write && !dir.exists() {
            fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            }
        }
        let path = dir.join("state.sqlite");
        no_symlink(&path)?;
        let lock = if write {
            let lockpath = dir.join("coordinator.lockfile");
            no_symlink(&lockpath)?;
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true).truncate(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = options.open(lockpath)?;
            file.try_lock_exclusive().context(
                "another coordinator owns this state directory; status/report remain available",
            )?;
            Some(file)
        } else {
            None
        };
        if write && !path.exists() {
            drop(private_file(&path)?);
        }
        let conn = Connection::open_with_flags(
            &path,
            if write {
                OpenFlags::SQLITE_OPEN_READ_WRITE
            } else {
                OpenFlags::SQLITE_OPEN_READ_ONLY
            },
        )?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        ensure!(
            version <= 4,
            "state database was created by a newer schema; refusing to modify it"
        );
        if write {
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "synchronous", "FULL")?;
            if version == 0 {
                conn.execute_batch("BEGIN IMMEDIATE;
                    CREATE TABLE targets(id TEXT PRIMARY KEY,record TEXT NOT NULL);
                    CREATE TABLE jobs(id INTEGER PRIMARY KEY,spec TEXT NOT NULL,spec_hash TEXT NOT NULL UNIQUE,
                        target_id TEXT NOT NULL REFERENCES targets(id),allocation TEXT NOT NULL,status TEXT NOT NULL,
                        created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,elapsed_ms INTEGER NOT NULL DEFAULT 0,
                        finding_id INTEGER,error TEXT);
                    CREATE TABLE work_units(id INTEGER PRIMARY KEY,job_id INTEGER NOT NULL REFERENCES jobs(id),
                        start TEXT NOT NULL,end TEXT NOT NULL,next TEXT NOT NULL,status TEXT NOT NULL,
                        generation INTEGER NOT NULL DEFAULT 0,UNIQUE(job_id,start));
                    CREATE INDEX pending_work ON work_units(job_id,status,id);
                    CREATE TABLE findings(id INTEGER PRIMARY KEY,target_id TEXT NOT NULL REFERENCES targets(id),
                        job_id INTEGER REFERENCES jobs(id),method TEXT NOT NULL,public_record TEXT NOT NULL,
                        private_pem BLOB NOT NULL,created_at INTEGER NOT NULL);
                    PRAGMA user_version=1;
                    COMMIT;")?;
            }
            if version < 2 {
                conn.execute_batch("BEGIN IMMEDIATE;CREATE TABLE audit_runs(id INTEGER PRIMARY KEY,public_record TEXT NOT NULL,created_at INTEGER NOT NULL);PRAGMA user_version=2;COMMIT;")?;
            }
            if version < 3 {
                conn.execute_batch("BEGIN IMMEDIATE;CREATE TABLE engine_states(job_id INTEGER PRIMARY KEY REFERENCES jobs(id),record TEXT NOT NULL);PRAGMA user_version=3;COMMIT;")?;
            }
            if version < 4 {
                conn.execute_batch("BEGIN IMMEDIATE;CREATE TABLE kangaroo_states(job_id INTEGER NOT NULL REFERENCES jobs(id),unit_id INTEGER PRIMARY KEY REFERENCES work_units(id),record TEXT NOT NULL,checksum TEXT NOT NULL);CREATE INDEX kangaroo_jobs ON kangaroo_states(job_id);PRAGMA user_version=4;COMMIT;")?;
            }
        } else {
            ensure!((1..=4).contains(&version), "uninitialized state database");
        }
        Ok(Self {
            conn,
            _lock: lock,
            path,
        })
    }

    pub fn import(&self, mut target: Target) -> Result<String> {
        if let Some(old) = self
            .conn
            .query_row(
                "SELECT record FROM targets WHERE id=?1",
                [&target.id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            let mut existing: Target = serde_json::from_str(&old)?;
            import::merge(&mut existing, target);
            target = existing;
        }
        self.conn.execute("INSERT INTO targets(id,record) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET record=excluded.record",params![target.id,serde_json::to_string(&target)?])?;
        Ok(target.id)
    }

    pub fn target(&self, id: &str) -> Result<Target> {
        let record: String = self
            .conn
            .query_row("SELECT record FROM targets WHERE id=?1", [id], |r| r.get(0))
            .with_context(|| format!("target not found: {id}"))?;
        let target: Target = serde_json::from_str(&record)?;
        import::public_key(&target)?;
        Ok(target)
    }

    pub fn targets(&self) -> Result<Vec<Target>> {
        let mut stmt = self
            .conn
            .prepare("SELECT record FROM targets ORDER BY id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.map(|r| Ok(serde_json::from_str(&r?)?)).collect()
    }

    pub fn create_job(&self, spec: &SearchSpec) -> Result<i64> {
        spec.validate()?;
        self.target(&spec.target_id)?;
        let hash = spec.hash()?;
        let allocation = canonical(&spec.work_bounds()?.0);
        self.conn.execute("INSERT OR IGNORE INTO jobs(spec,spec_hash,target_id,allocation,status,created_at,updated_at) VALUES(?1,?2,?3,?4,'queued',?5,?5)",params![serde_json::to_string(spec)?,hash,spec.target_id,allocation,now()])?;
        Ok(self
            .conn
            .query_row("SELECT id FROM jobs WHERE spec_hash=?1", [hash], |r| {
                r.get(0)
            })?)
    }

    pub fn spec(&self, id: i64) -> Result<SearchSpec> {
        let (s, hash): (String, String) = self
            .conn
            .query_row("SELECT spec,spec_hash FROM jobs WHERE id=?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .context("job not found")?;
        let spec: SearchSpec = serde_json::from_str(&s)?;
        spec.validate()?;
        ensure!(
            spec.hash()? == hash,
            "stored job specification checksum mismatch"
        );
        Ok(spec)
    }

    pub fn status(&self, id: i64) -> Result<String> {
        Ok(self
            .conn
            .query_row("SELECT status FROM jobs WHERE id=?1", [id], |r| r.get(0))?)
    }

    pub fn begin_run(&mut self, id: i64) -> Result<()> {
        self.spec(id)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE work_units SET status='pending' WHERE job_id=?1 AND status='running'",
            [id],
        )?;
        tx.execute(
            "UPDATE jobs SET status='running',error=NULL,updated_at=?2 WHERE id=?1",
            params![id, now()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn allocate(&mut self, id: i64) -> Result<Option<WorkUnit>> {
        let spec = self.spec(id)?;
        let (domain_start, domain_end) = spec.work_bounds()?;
        let tx = self.conn.transaction()?;
        let pending:Option<(i64,String,String,String,i64)>=tx.query_row("SELECT id,start,end,next,generation FROM work_units WHERE job_id=?1 AND status='pending' ORDER BY id LIMIT 1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        let (unit_id, start, end, next, generation) = if let Some((unit, a, b, c, g)) = pending {
            tx.execute(
                "UPDATE work_units SET status='running',generation=generation+1 WHERE id=?1",
                [unit],
            )?;
            (unit, number(&a)?, number(&b)?, number(&c)?, g + 1)
        } else {
            let allocation: String =
                tx.query_row("SELECT allocation FROM jobs WHERE id=?1", [id], |r| {
                    r.get(0)
                })?;
            let start = number(&allocation)?;
            let limit = domain_end.clone();
            if start >= limit {
                return Ok(None);
            }
            let end = (&start + BigUint::from(spec.chunk_size)).min(limit);
            tx.execute("INSERT INTO work_units(job_id,start,end,next,status,generation) VALUES(?1,?2,?3,?2,'running',1)",params![id,canonical(&start),canonical(&end)])?;
            let unit = tx.last_insert_rowid();
            tx.execute(
                "UPDATE jobs SET allocation=?2 WHERE id=?1",
                params![id, canonical(&end)],
            )?;
            (unit, start.clone(), end, start, 1)
        };
        ensure!(
            domain_start <= start && start <= next && next <= end && end <= domain_end,
            "stored work bounds are invalid"
        );
        tx.commit()?;
        Ok(Some(WorkUnit {
            id: unit_id,
            generation,
            start,
            end,
            next,
        }))
    }

    pub fn progress(
        &mut self,
        job: i64,
        unit: i64,
        generation: i64,
        next: &BigUint,
        finished: bool,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        let (old, end, g, status): (String, String, i64, String) = tx.query_row(
            "SELECT next,end,generation,status FROM work_units WHERE id=?1 AND job_id=?2",
            params![unit, job],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        ensure!(
            g == generation && status == "running",
            "stale work-unit update"
        );
        let end = number(&end)?;
        ensure!(
            number(&old)? <= *next && *next <= end,
            "invalid or regressing work cursor"
        );
        let status = if *next == end {
            "done"
        } else if finished {
            "pending"
        } else {
            "running"
        };
        tx.execute(
            "UPDATE work_units SET next=?2,status=?3 WHERE id=?1",
            params![unit, canonical(next), status],
        )?;
        tx.execute(
            "UPDATE jobs SET updated_at=?2 WHERE id=?1",
            params![job, now()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_recovery(
        &mut self,
        target: &Target,
        job: Option<i64>,
        method: &str,
        pem: &[u8],
    ) -> Result<i64> {
        crate::crypto::verify_private(target, pem)?;
        let public = json!({"target_id":target.id,"method":method,"outcome":"verified_recovery","private_material":"stored in private state database; excluded from reports"});
        let tx = self.conn.transaction()?;
        tx.execute("INSERT INTO findings(target_id,job_id,method,public_record,private_pem,created_at) VALUES(?1,?2,?3,?4,?5,?6)",params![target.id,job,method,public.to_string(),pem,now()])?;
        let finding = tx.last_insert_rowid();
        if let Some(job) = job {
            tx.execute(
                "UPDATE jobs SET status='recovered',finding_id=?2,updated_at=?3 WHERE id=?1",
                params![job, finding, now()],
            )?;
        }
        tx.commit()?;
        Ok(finding)
    }

    pub fn finish(
        &self,
        id: i64,
        status: &str,
        elapsed: Duration,
        error: Option<&str>,
    ) -> Result<()> {
        self.conn.execute("UPDATE jobs SET status=CASE WHEN finding_id IS NOT NULL THEN 'recovered' ELSE ?2 END,elapsed_ms=elapsed_ms+?3,updated_at=?4,error=?5 WHERE id=?1",params![id,status,elapsed.as_millis().min(i64::MAX as u128) as i64,now(),error])?;
        Ok(())
    }

    pub fn report(&self, id: i64) -> Result<Value> {
        let spec = self.spec(id)?;
        let (domain_start, domain_end) = spec.work_bounds()?;
        let (status, created, updated, elapsed, finding, error): (
            String,
            i64,
            i64,
            i64,
            Option<i64>,
            Option<String>,
        ) = self.conn.query_row(
            "SELECT status,created_at,updated_at,elapsed_ms,finding_id,error FROM jobs WHERE id=?1",
            [id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )?;
        let mut stmt = self
            .conn
            .prepare("SELECT start,next FROM work_units WHERE job_id=?1")?;
        let rows = stmt.query_map([id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut spans = vec![];
        let mut work_count = BigUint::zero();
        for row in rows {
            let (a, b) = row?;
            let (a, b) = (number(&a)?, number(&b)?);
            ensure!(
                domain_start <= a && a <= b && b <= domain_end,
                "stored coverage outside search bounds"
            );
            work_count += &b - &a;
            if let Some(c) = &spec.bsgs {
                let base = number(&spec.start)?;
                let m = BigUint::from(c.baby_steps);
                spans.push((&base + &a * &m, (&base + &b * &m).min(number(&spec.end)?)));
            } else if spec.kangaroo.is_none() {
                spans.push((a, b));
            }
        }
        let coverage = merged_coverage(spans)?;
        let count = coverage.iter().try_fold(BigUint::zero(), |sum, c| {
            Ok::<_, anyhow::Error>(sum + number(&c.end)? - number(&c.start)?)
        })?;
        let outcome = match status.as_str() {
            "recovered" => "verified_recovery",
            "exhausted" => "range_exhausted",
            "budget_exhausted" => "probabilistic_budget_exhausted",
            "failed" => "engine_failure",
            "paused" => "interrupted",
            _ => "in_progress",
        };
        let bsgs = spec.bsgs.is_some();
        let mut result = json!({"format_version":2,"job_id":id,"spec":spec,"status":status,"outcome":outcome,"covered_candidates":count.to_str_radix(10),"tested_candidates":if bsgs {None} else {Some(count.to_str_radix(10))},"giant_steps_completed":if bsgs {Some(work_count.to_str_radix(10))} else {None},"coverage":coverage,"engine_state":self.engine_state(id)?,"finding_id":finding,"created_at":created,"last_durable_update":updated,"completed_run_elapsed_ms":elapsed,"error":error,"coverage_note":if bsgs {"half-open scalar intervals algebraically covered by completed giant lookups, not brute-force candidate attempts"} else {"half-open intervals; uncommitted work may replay after a crash; no general security guarantee"},"status_note":"status is last persisted lifecycle; a forced termination can leave it running until resume","timing_note":"elapsed time includes finished invocations; a killed invocation may be undercounted","secret_storage":"private-file permissions; not encrypted at rest"});
        if spec.kangaroo.is_some() {
            result["format_version"] = json!(3);
            result["covered_candidates"] = Value::Null;
            result["tested_candidates"] = Value::Null;
            result["coverage"] = Value::Null;
            let metrics = crate::kangaroo::report(self, id)?;
            for (key, value) in metrics.as_object().context("invalid walk report")? {
                result[key] = value.clone();
            }
        }
        Ok(result)
    }

    pub fn initialize_kangaroo(
        &mut self,
        job: i64,
        spec: &SearchSpec,
        initial: &crate::kangaroo::Snapshot,
    ) -> Result<()> {
        let config = spec
            .kangaroo
            .as_ref()
            .context("missing kangaroo configuration")?;
        if let Some(manifest) = self.engine_state(job)? {
            ensure!(
                manifest == json!({"version":1,"engine":"ec-kangaroo","spec_hash":spec.hash()?}),
                "kangaroo manifest binding mismatch"
            );
            let units: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM work_units WHERE job_id=?1",
                [job],
                |r| r.get(0),
            )?;
            let states: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM kangaroo_states WHERE job_id=?1",
                [job],
                |r| r.get(0),
            )?;
            ensure!(
                units == i64::from(config.attempts) && states == units,
                "missing kangaroo walk state; refusing reset"
            );
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        let units: i64 = tx.query_row(
            "SELECT COUNT(*) FROM work_units WHERE job_id=?1",
            [job],
            |r| r.get(0),
        )?;
        ensure!(
            units == 0,
            "missing kangaroo manifest with existing work; refusing reset"
        );
        for attempt in 0..config.attempts {
            let mut state = initial.clone();
            state.attempt = attempt;
            state.validate(spec, attempt)?;
            tx.execute("INSERT INTO work_units(job_id,start,end,next,status,generation) VALUES(?1,?2,?3,?2,'pending',0)",params![job,canonical(&attempt.into()),canonical(&(attempt+1).into())])?;
            let unit = tx.last_insert_rowid();
            let record = serde_json::to_string(&state)?;
            tx.execute(
                "INSERT INTO kangaroo_states(job_id,unit_id,record,checksum) VALUES(?1,?2,?3,?4)",
                params![
                    job,
                    unit,
                    record,
                    crate::model::fingerprint(record.as_bytes())
                ],
            )?;
        }
        tx.execute(
            "UPDATE jobs SET allocation=?2 WHERE id=?1",
            params![job, canonical(&config.attempts.into())],
        )?;
        tx.execute(
            "INSERT INTO engine_states(job_id,record) VALUES(?1,?2)",
            params![
                job,
                json!({"version":1,"engine":"ec-kangaroo","spec_hash":spec.hash()?}).to_string()
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn kangaroo_state(
        &self,
        job: i64,
        unit: &WorkUnit,
        spec: &SearchSpec,
    ) -> Result<Option<crate::kangaroo::Snapshot>> {
        use num_traits::ToPrimitive;
        let config = spec
            .kangaroo
            .as_ref()
            .context("missing kangaroo configuration")?;
        let max_bytes = u64::from(config.max_points) * 512 + 8192;
        let (record,checksum):(String,String)=self.conn.query_row("SELECT record,checksum FROM kangaroo_states WHERE job_id=?1 AND unit_id=?2 AND length(record)<=?3",params![job,unit.id,max_bytes as i64],|r|Ok((r.get(0)?,r.get(1)?))).context("missing or oversized kangaroo checkpoint")?;
        ensure!(
            crate::model::fingerprint(record.as_bytes()) == checksum,
            "kangaroo checkpoint checksum mismatch"
        );
        let state: crate::kangaroo::Snapshot = serde_json::from_str(&record)?;
        let attempt = unit.start.to_u32().context("invalid logical attempt")?;
        ensure!(
            unit.end == &unit.start + 1u8,
            "invalid kangaroo unit bounds"
        );
        state.validate(spec, attempt)?;
        ensure!(
            (state.phase == "done") == (unit.next == unit.end),
            "kangaroo walk state and work cursor disagree"
        );
        Ok(Some(state))
    }

    pub fn save_kangaroo_state(
        &mut self,
        job: i64,
        unit: &WorkUnit,
        spec: &SearchSpec,
        state: &crate::kangaroo::Snapshot,
        finished: bool,
    ) -> Result<()> {
        use num_traits::ToPrimitive;
        state.validate(spec, unit.start.to_u32().context("invalid attempt")?)?;
        let old = self
            .kangaroo_state(job, unit, spec)?
            .context("missing old walk")?;
        ensure!(
            old.tame_steps <= state.tame_steps
                && old.wild_steps <= state.wild_steps
                && number(&old.tame_distance)? <= number(&state.tame_distance)?
                && number(&old.wild_distance)? <= number(&state.wild_distance)?,
            "regressing kangaroo checkpoint"
        );
        ensure!(
            old.points
                .iter()
                .all(|(p, d)| state.points.get(p) == Some(d)),
            "kangaroo checkpoint lost committed points"
        );
        let rank = |p: &str| match p {
            "tame" => 0,
            "wild" => 1,
            _ => 2,
        };
        ensure!(
            rank(&old.phase) <= rank(&state.phase),
            "regressing kangaroo phase"
        );
        let record = serde_json::to_string(state)?;
        let checksum = crate::model::fingerprint(record.as_bytes());
        let tx = self.conn.transaction()?;
        let (generation, status): (i64, String) = tx.query_row(
            "SELECT generation,status FROM work_units WHERE id=?1 AND job_id=?2",
            params![unit.id, job],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            generation == unit.generation && status == "running",
            "stale kangaroo checkpoint"
        );
        let done = state.phase == "done";
        ensure!(
            !done || finished,
            "completed walk must finish its work unit"
        );
        tx.execute(
            "UPDATE kangaroo_states SET record=?2,checksum=?3 WHERE unit_id=?1",
            params![unit.id, record, checksum],
        )?;
        tx.execute(
            "UPDATE work_units SET next=?2,status=?3 WHERE id=?1",
            params![
                unit.id,
                canonical(if done { &unit.end } else { &unit.start }),
                if done {
                    "done"
                } else if finished {
                    "pending"
                } else {
                    "running"
                }
            ],
        )?;
        tx.execute(
            "UPDATE jobs SET updated_at=?2 WHERE id=?1",
            params![job, now()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn engine_state(&self, job: i64) -> Result<Option<Value>> {
        let version: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version < 3 {
            return Ok(None);
        }
        let record: Option<String> = self
            .conn
            .query_row(
                "SELECT record FROM engine_states WHERE job_id=?1",
                [job],
                |r| r.get(0),
            )
            .optional()?;
        record
            .map(|r| serde_json::from_str(&r).map_err(Into::into))
            .transpose()
    }

    pub fn save_engine_state(&mut self, job: i64, record: &Value) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("INSERT INTO engine_states(job_id,record) VALUES(?1,?2) ON CONFLICT(job_id) DO UPDATE SET record=excluded.record",params![job,record.to_string()])?;
        tx.execute(
            "UPDATE jobs SET updated_at=?2 WHERE id=?1",
            params![job, now()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn jobs(&self) -> Result<Vec<Value>> {
        let mut stmt = self.conn.prepare("SELECT id FROM jobs ORDER BY id")?;
        let ids = stmt
            .query_map([], |r| r.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter().map(|id| self.report(id)).collect()
    }

    pub fn findings(&self) -> Result<Vec<Value>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id,public_record FROM findings ORDER BY id")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        rows.map(|row| {
            let (id, s) = row?;
            let mut v: Value = serde_json::from_str(&s)?;
            v["finding_id"] = json!(id);
            Ok(v)
        })
        .collect()
    }

    pub fn save_audit(&self, report: &Value) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO audit_runs(public_record,created_at) VALUES(?1,?2)",
            params![report.to_string(), now()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn audits(&self) -> Result<Vec<Value>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id,public_record,created_at FROM audit_runs ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        rows.map(|row| {
            let (id, record, created) = row?;
            let record: Value = serde_json::from_str(&record)?;
            Ok(json!({"audit_id":id,"created_at":created,"report":record}))
        })
        .collect()
    }

    pub fn export_key(&self, id: i64, path: &Path) -> Result<()> {
        let (target, pem): (String, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT target_id,private_pem FROM findings WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .context("finding not found")?;
        crate::crypto::verify_private(&self.target(&target)?, &pem)?;
        let mut file = private_file(path)?;
        use std::io::Write;
        file.write_all(&pem)?;
        file.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn locks_and_readers() {
        let dir = tempfile::tempdir().unwrap();
        let first = Store::open(dir.path(), true).unwrap();
        assert!(Store::open(dir.path(), true).is_err());
        assert!(Store::open(dir.path(), false).is_ok());
        drop(first);
        assert!(Store::open(dir.path(), true).is_ok());
    }
}
