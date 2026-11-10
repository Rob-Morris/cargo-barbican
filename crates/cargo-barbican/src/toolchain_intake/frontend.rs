use super::{
    acceptance,
    admission::{self, AcceptedContext},
    paths::Stores,
    repo::{self, RepoContext},
    review,
    trust::{self, Trust},
};
use crate::cli::{
    AuditOutputFormat, Cli, Command, GatehouseCommand, ToolchainCommand, ToolchainOperationArgs,
    ToolchainProfile, ToolchainTrustCommand,
};
use barbican::rust_distribution::{Encoding, Profile, SelectionRequest};
use barbican::toolchain_admission::{
    EligibilityPurpose, FreshnessRequest, PortableReview, parse_record,
};
use barbican::{OffsetDateTime, Sha256Digest};
use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

type Result<T> = std::result::Result<T, String>;

pub(crate) fn is_static(cli: &Cli) -> bool {
    matches!(&cli.command,Command::Toolchain{command} if !matches!(command,ToolchainCommand::Check))
}

pub(crate) fn run(
    cli: &Cli,
    current: &Path,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    real_cli: bool,
) -> Result<ExitCode> {
    let Command::Toolchain { command } = &cli.command else {
        return Err("not a toolchain intake command".into());
    };
    let now = now.unix_timestamp();
    if let ToolchainCommand::Trust { command, format } = command {
        let stores = Stores::open(
            current,
            cli.repo.as_deref(),
            cli.data_dir.as_deref(),
            cli.cache_dir.as_deref(),
        )?;
        let seed = trust::bundled_seed()?;
        let trust = Trust::load(&stores.data, &seed, now)?;
        let result = match command {
            ToolchainTrustCommand::Show => {
                json!({"schema_version":1,"operation":"trust-show","status":"local-approved-baseline","material_id":trust.baseline.material.id()?,"fingerprint":trust.baseline.material.fingerprint,"purpose":trust.baseline.material.purpose,"source":trust.baseline.material.source,"approved_at":trust.baseline.approved_at,"checked_at":trust.baseline.checked_at,"adverse_knowledge":trust.observations()?,"pending_bundle_proposal":trust.pending_bundle_proposal,"proposal_directory":stores.data.root().join("trust/proposals"),"limitation":"An unchanged fetch does not prove current nonrevocation. Personal GPG trust and secret keys are not used."})
            }
            ToolchainTrustCommand::Refresh {
                public_key,
                fingerprint,
            } => {
                let mut material = trust.baseline.material.clone();
                if let Some(path) = public_key {
                    material.certificate = read_input(current, path)?;
                    material.fingerprint = fingerprint
                        .as_ref()
                        .ok_or("explicit public key requires its complete primary fingerprint")?
                        .to_ascii_uppercase();
                    material.source = "explicit operator-supplied public certificate".into();
                } else {
                    material.certificate =
                        super::sources::Sources::new().fetch(trust::OFFICIAL_KEY_URL)?;
                }
                match trust.stage(material, now)? {
                    trust::Refresh::Unchanged => {
                        json!({"schema_version":1,"operation":"trust-refresh","status":"unchanged","approved_at":trust.baseline.approved_at,"checked_at":now})
                    }
                    trust::Refresh::Proposed(id) => {
                        let proposal = trust.proposal(&id)?;
                        json!({"schema_version":1,"operation":"trust-refresh","status":"approval-required","proposal_id":id,"proposal_path":stores.data.root().join(format!("trust/proposals/{id}.json")),"base_material_id":proposal.base_id,"old_material":{"fingerprint":trust.baseline.material.fingerprint,"purpose":trust.baseline.material.purpose,"source":trust.baseline.material.source,"certificate_sha256":barbican::toolchain_admission::digest_bytes(&trust.baseline.material.certificate)},"proposed_material":{"fingerprint":proposal.material.fingerprint,"purpose":proposal.material.purpose,"source":proposal.material.source,"certificate_sha256":barbican::toolchain_admission::digest_bytes(&proposal.material.certificate)},"next_action":format!("Inspect the exact public proposal file and this diff, then cargo-barbican toolchain trust approve {id}")})
                    }
                }
            }
            ToolchainTrustCommand::Approve { proposal_id } => {
                let id = digest(proposal_id)?;
                trust.approve(&id, now)?;
                json!({"schema_version":1,"operation":"trust-approve","status":"approved","proposal_id":id})
            }
        };
        return output(stdout, *format, &result);
    }
    if let ToolchainCommand::Review {
        release,
        standalone,
        host,
        profile,
        components,
        targets,
        min_age_days,
        format,
    } = command
    {
        let repo = resolve_repo(cli, current, *standalone)?;
        let policy = review::invocation_policy(repo.as_ref(), *min_age_days)?;
        let host = host.clone().unwrap_or_else(default_host);
        let mut request = if let Some(repo) = &repo {
            match repo::read_optional(&repo.root, Path::new("rust-toolchain.toml"))? {
                Some(bytes) => {
                    barbican::rust_distribution::parse_repository_selection(
                        std::str::from_utf8(&bytes).map_err(|e| e.to_string())?,
                        &host,
                        Encoding::Xz,
                    )
                    .map_err(|e| e.to_string())?
                    .1
                }
                None => SelectionRequest {
                    host: host.clone(),
                    profile: Profile::Minimal,
                    components: Vec::new(),
                    targets: Vec::new(),
                    encoding: Encoding::Xz,
                },
            }
        } else {
            SelectionRequest {
                host,
                profile: Profile::Minimal,
                components: Vec::new(),
                targets: Vec::new(),
                encoding: Encoding::Xz,
            }
        };
        if let Some(profile) = profile {
            request.profile = match profile {
                ToolchainProfile::Minimal => Profile::Minimal,
                ToolchainProfile::Default => Profile::Default,
            };
        }
        request.components.extend(components.clone());
        request.components.sort();
        request.components.dedup();
        request.targets.extend(targets.clone());
        request.targets.sort();
        request.targets.dedup();
        let stores = Stores::open(
            current,
            repo.as_ref().map(|r| r.root.as_path()),
            cli.data_dir.as_deref(),
            cli.cache_dir.as_deref(),
        )?;
        let (id, review) = review::create(
            release,
            &request,
            policy,
            &stores.data,
            &stores.cache,
            &trust::bundled_seed()?,
            now,
        )?;
        if let Some(repo) = &repo {
            repo.recheck()?;
        }
        let repeated_age = min_age_days
            .map(|days| format!(" --min-age-days {days}"))
            .unwrap_or_default();
        let standalone_option = if repo.is_none() { " --standalone" } else { "" };
        return output(
            stdout,
            *format,
            &json!({"schema_version":1,"operation":"review","status":"human-review-required","review_id":id,"subject":review.subject.record(),"evidence":review.record.evidence,"policy":review.record.policy,"review_template":stores.data.root().join(format!("reviews/{id}.md")),"dossier_directory":stores.data.root().join(&review.record.snapshot_root),"source_directory":stores.data.root().join(&review.record.snapshot_root).join(format!("docs/dependency-reviews/toolchains/{}/sources",review.subject.id())),"next_action":format!("Complete the exact review and residual findings; using these same storage and repository options, run cargo-barbican toolchain accept {id} --record <completed-path>{standalone_option}{repeated_age}"),"limitations":["Static review is not installation or compatibility verification.","Archive metadata support is broader than qualified native evaluator support.","Official supplier trust cannot prove fresh nonrevocation or universal benignness."]}),
        );
    }
    let (id_text, options) = match command {
        ToolchainCommand::Accept {
            review_id, options, ..
        }
        | ToolchainCommand::Install {
            review_id, options, ..
        }
        | ToolchainCommand::Adopt { review_id, options }
        | ToolchainCommand::InstallationCheck { review_id, options }
        | ToolchainCommand::Activate { review_id, options } => (Some(review_id.as_str()), options),
        ToolchainCommand::AdmissionCheck { review_id, options } => (review_id.as_deref(), options),
        _ => return Err("legacy toolchain conformance must use its existing dispatcher".into()),
    };
    let repo = resolve_repo(cli, current, options.standalone)?;
    let current_policy = review::invocation_policy(repo.as_ref(), options.min_age_days)?;
    let stores = Stores::open(
        current,
        repo.as_ref().map(|r| r.root.as_path()),
        cli.data_dir.as_deref(),
        cli.cache_dir.as_deref(),
    )?;
    let id = match id_text {
        Some(id) => digest(id)?,
        None => repo_review_id(
            repo.as_ref()
                .ok_or("admission-check requires --repo or an explicit review ID")?,
        )?,
    };
    let seed = trust::bundled_seed()?;
    let freshness = freshness(
        options,
        now,
        matches!(
            command,
            ToolchainCommand::Activate { .. }
                | ToolchainCommand::AdmissionCheck { .. }
                | ToolchainCommand::InstallationCheck { .. }
        ),
    )?;
    if let ToolchainCommand::Accept { record, .. } = command {
        let imported = stores
            .data
            .read_optional(Path::new(&format!("reviews/{id}.json")), 8 * 1024 * 1024)?
            .is_none();
        if imported {
            review::import_portable(&stores.data,&stores.cache,repo.as_ref().ok_or("empty local state requires explicit --repo with reviewed portable inputs, or collect a standalone review first")?,&id,options.cached_admission,now)?;
        }
        let review = if matches!(freshness, FreshnessRequest::Online { .. }) && !imported {
            review::refresh(&stores.data, &id, &seed, now)?
        } else {
            review::load(&stores.data, &id, &seed, now)?
        };
        review::require_current_policy(&review.record.policy, &current_policy)?;
        let prose = read_input(current, record)?;
        let mut assessment = acceptance::assess(&review, &id, &prose, now)?;
        if let Some(repo) = &repo
            && let Some(original) = acceptance::portable_assessment(repo, &review, &id, &prose)?
        {
            assessment = original;
        }
        let knowledge = admission::knowledge(&stores.data, &review.subject)?;
        let (accepted, operation) = acceptance::publish_personal(
            &stores.data,
            &id,
            &review,
            assessment,
            prose,
            freshness.clone(),
            &knowledge,
            repo.as_ref(),
            now,
        )?;
        let admission = repo
            .as_ref()
            .map(|repo| {
                admission::publish_repository(
                    &stores.data,
                    &review,
                    &accepted,
                    repo,
                    freshness,
                    now,
                )
            })
            .transpose()?;
        return output(
            stdout,
            options.format,
            &json!({"schema_version":1,"operation":"accept","status":"personally-accepted","review_id":id,"accepted_at":accepted.acceptance.accepted_at,"eligibility":operation,"repository_admission":admission,"limitation":"Acceptance does not install, execute, activate or certify compatibility."}),
        );
    }
    let home = rustup_home(current, options)?;
    let context = AcceptedContext::load(
        &stores.data,
        id.clone(),
        repo,
        current_policy,
        freshness,
        now,
    )?;
    let accepted_slot = format!(
        "{}-{}",
        context.review.subject.record().release,
        context.review.subject.record().host
    );
    super::paths::validate_native_selection(
        context
            .repository
            .as_ref()
            .map(|repo| repo.root.as_path())
            .unwrap_or(current),
        &home,
        Some(&accepted_slot),
    )?;
    match command {
        ToolchainCommand::AdmissionCheck { .. } => {
            context.continuing_check(&home, now)?;
            output(
                stdout,
                options.format,
                &json!({"schema_version":1,"operation":"admission-check","status":"admitted-installed-verified","review_id":id,"mode":"continuing-local","limitation":"Current repository policy and installed scope only; no compatibility or universal security verdict."}),
            )
        }
        ToolchainCommand::InstallationCheck { .. } => {
            let (actual, installed) = context.installed(&home)?;
            let eligible = context.recheck_before_effects(
                EligibilityPurpose::InstallationInspection,
                Some(&installed),
                now,
            )?;
            output(
                stdout,
                options.format,
                &json!({"schema_version":1,"operation":"installation-check","status":"installed-verified","review_id":id,"eligibility":super::operation::OperationEvidence::new("installation-check",&eligible,now),"checked_files":actual.checked_files}),
            )
        }
        ToolchainCommand::Adopt { .. } => {
            let (actual, operation) = context.adopt(&home, now)?;
            output(
                stdout,
                options.format,
                &json!({"schema_version":1,"operation":"adopt","status":"adopted-installed-verified","review_id":id,"eligibility":operation,"checked_files":actual.checked_files,"limitation":"Static correspondence does not approve historical execution or side effects."}),
            )
        }
        ToolchainCommand::Install {
            rustup_executable,
            allow_initial_default,
            ..
        } => {
            if !real_cli {
                return Err("native installation requires the direct trusted cargo-barbican process entrypoint".into());
            }
            let cancellation = super::installation::NativeCancellation::install()?;
            let (outcome, operation) = context.install(
                &home,
                rustup_executable,
                *allow_initial_default,
                cancellation.flag(),
                now,
            )?;
            super::installation::check_cancelled(cancellation.flag(), "before installation result output")
                .map_err(|error| format!("{error}; installed data retained at {}; initial default assigned: {}; any completed continuing-use binding retained; repository pin unchanged", outcome.correspondence.slot.display(), outcome.initial_default_assigned))?;
            output(
                stdout,
                options.format,
                &json!({"schema_version":1,"operation":"install","status":"installed-verified","review_id":id,"eligibility":operation,"already_present":outcome.already_present,"initial_default_assigned":outcome.initial_default_assigned,"checked_files":outcome.correspondence.checked_files}),
            )
        }
        ToolchainCommand::Activate { .. } => {
            if !real_cli {
                return Err(
                    "activation requires the direct trusted cargo-barbican process entrypoint"
                        .into(),
                );
            }
            let cancellation = super::installation::NativeCancellation::install()?;
            let (outcome, operation) = context.activate(&home, cancellation.flag(), now)?;
            output(
                stdout,
                options.format,
                &json!({"schema_version":1,"operation":"activate","status":"activated-compatibility-unchecked","review_id":id,"eligibility":operation,"changed":outcome.changed,"pin":outcome.pin,"next_action":"Run the existing explicit verify or gatehouse pre-release command."}),
            )
        }
        _ => Err("unsupported intake dispatch".into()),
    }
}

fn digest(value: &str) -> Result<Sha256Digest> {
    Sha256Digest::try_from(value).map_err(|e| e.to_string())
}
fn default_host() -> String {
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        "unqualified"
    };
    let os = if cfg!(target_os = "macos") {
        "apple-darwin"
    } else if cfg!(target_os = "linux") {
        "unknown-linux-gnu"
    } else {
        "unqualified"
    };
    format!("{arch}-{os}")
}
fn resolve_repo(cli: &Cli, current: &Path, standalone: bool) -> Result<Option<RepoContext>> {
    if standalone {
        if cli.repo.is_some() {
            return Err("--standalone conflicts with --repo".into());
        }
        return Ok(None);
    }
    if let Some(path) = &cli.repo {
        return RepoContext::capture(&if path.is_absolute() {
            path.clone()
        } else {
            current.join(path)
        })
        .map(Some);
    }
    if repo::read_optional(current, Path::new("Cargo.toml"))?.is_some() {
        return RepoContext::capture(current).map(Some);
    }
    if current
        .ancestors()
        .skip(1)
        .any(|path| path.join("Cargo.toml").exists())
    {
        return Err("nested repository intent is ambiguous before Cargo discovery; use --repo <root> or explicit --standalone".into());
    }
    Ok(None)
}
fn freshness(
    options: &ToolchainOperationArgs,
    now: i64,
    continuing: bool,
) -> Result<FreshnessRequest> {
    if options.cached_admission {
        let reason = options
            .cache_reason
            .as_deref()
            .ok_or("--cached-admission requires --cache-reason")?;
        if reason.trim().is_empty() {
            return Err("cached admission reason must not be empty".into());
        }
        Ok(FreshnessRequest::Cached {
            reason: reason.into(),
        })
    } else if continuing {
        Ok(FreshnessRequest::Local)
    } else {
        Ok(FreshnessRequest::Online {
            operation_started_at: now,
        })
    }
}
fn rustup_home(current: &Path, options: &ToolchainOperationArgs) -> Result<PathBuf> {
    let path = options
        .rustup_home
        .clone()
        .or_else(|| std::env::var_os("RUSTUP_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")))
        .ok_or("RUSTUP_HOME/HOME unavailable; provide --rustup-home")?;
    Ok(if path.is_absolute() {
        path
    } else {
        current.join(path)
    })
}
fn read_input(current: &Path, path: &Path) -> Result<Vec<u8>> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        current.join(path)
    };
    let parent = path
        .parent()
        .ok_or("input has no parent")?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let name = path.file_name().ok_or("input has no filename")?;
    repo::read_optional(&parent, Path::new(name))?.ok_or("input file is missing".into())
}
fn output(stdout: &mut dyn Write, format: AuditOutputFormat, value: &Value) -> Result<ExitCode> {
    if format == AuditOutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, value).map_err(|e| e.to_string())?;
        writeln!(stdout).map_err(|e| e.to_string())?;
    } else {
        let mut line = |text: String| -> Result<()> {
            writeln!(
                stdout,
                "{}",
                crate::commands::escape_diagnostic_for_terminal(&text)
            )
            .map_err(|e| e.to_string())
        };
        line(format!(
            "{}: {}",
            value["operation"].as_str().unwrap_or("toolchain"),
            value["status"].as_str().unwrap_or("unknown")
        ))?;
        if let Some(subject) = value.get("subject") {
            line(format!(
                "Rust {} / {} / {} profile",
                subject["release"].as_str().unwrap_or("?"),
                subject["host"].as_str().unwrap_or("?"),
                subject["profile"].as_str().unwrap_or("?")
            ))?;
            if let Some(archives) = subject["archives"].as_array() {
                for archive in archives {
                    line(format!(
                        "  selected: {} / {} ({})",
                        archive["package"].as_str().unwrap_or("?"),
                        archive["target"].as_str().unwrap_or("?"),
                        archive["encoding"].as_str().unwrap_or("?")
                    ))?;
                }
            }
        }
        for key in [
            "review_id",
            "review_template",
            "dossier_directory",
            "source_directory",
            "fingerprint",
            "material_id",
            "purpose",
            "source",
            "approved_at",
            "checked_at",
            "accepted_at",
            "proposal_id",
            "proposal_path",
            "base_material_id",
            "pending_bundle_proposal",
            "proposal_directory",
            "checked_files",
            "initial_default_assigned",
            "already_present",
            "changed",
            "pin",
        ] {
            if let Some(field) = value.get(key).filter(|field| !field.is_null()) {
                line(format!(
                    "{key}: {}",
                    field
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| field.to_string())
                ))?;
            }
        }
        if let Some(policy) = value.get("policy") {
            line(format!(
                "Minimum release age: {} complete days",
                policy["minimum_days"]
            ))?;
        }
        if let Some(evidence) = value.get("evidence") {
            if let Some(components) = evidence["component_sources"].as_array() {
                for component in components {
                    line(format!(
                        "Component {} / {}: {} source {}",
                        component["archive"]["package"].as_str().unwrap_or("?"),
                        component["archive"]["target"].as_str().unwrap_or("?"),
                        component["corpus"].as_str().unwrap_or("?"),
                        component["source_revision"].as_str().unwrap_or("?")
                    ))?;
                    line(format!(
                        "  {}",
                        component["relationship"].as_str().unwrap_or("")
                    ))?;
                    line(format!(
                        "  Coverage limits: {}",
                        component["residual_coverage"].as_str().unwrap_or("")
                    ))?;
                }
            }
            if let Some(observations) = evidence["observations"].as_array() {
                for source in observations {
                    line(format!(
                        "Source {} / {}: {} (checked {})",
                        source["source"]["kind"].as_str().unwrap_or("?"),
                        source["source"]["scope"].as_str().unwrap_or("?"),
                        source["coverage"].as_str().unwrap_or("?"),
                        source["checked_at"]
                    ))?;
                    line(format!(
                        "  {}",
                        source["coverage_rationale"].as_str().unwrap_or("")
                    ))?;
                }
            }
            if let Some(findings) = evidence["findings"].as_array() {
                for finding in findings {
                    line(format!(
                        "Finding {}: {}",
                        finding["id"].as_str().unwrap_or("?"),
                        finding["rationale"].as_str().unwrap_or("")
                    ))?;
                }
            }
        }
        for key in [
            "old_material",
            "proposed_material",
            "adverse_knowledge",
            "eligibility",
            "repository_admission",
        ] {
            if let Some(field) = value.get(key).filter(|v| !v.is_null()) {
                line(format!("{key}: {field}"))?;
            }
        }
        if let Some(limits) = value.get("limitations").and_then(Value::as_array) {
            for limit in limits {
                line(format!("Scope: {}", limit.as_str().unwrap_or("")))?;
            }
        }
        for key in ["limitation", "next_action"] {
            if let Some(text) = value.get(key).and_then(Value::as_str) {
                line(text.into())?;
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn repo_review_id(repo: &RepoContext) -> Result<Sha256Digest> {
    let pin = repo::read_optional(&repo.root, Path::new("rust-toolchain.toml"))?
        .ok_or("canonical rust-toolchain.toml is required for admission-check")?;
    let (channel, request) = barbican::rust_distribution::parse_repository_selection(
        std::str::from_utf8(&pin).map_err(|e| e.to_string())?,
        &default_host(),
        Encoding::Xz,
    )
    .map_err(|e| e.to_string())?;
    let targets = repo::read_optional(&repo.root, Path::new("reviewed-targets.toml"))?
        .ok_or("reviewed-targets.toml is missing; explicitly review and accept this toolchain")?;
    let targets = barbican::parse_reviewed_targets_toml(
        std::str::from_utf8(&targets).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let mut matches = Vec::new();
    for admission in targets.rust_toolchains() {
        let bytes = repo::read_optional(&repo.root, Path::new(&admission.evidence_record))?
            .ok_or("declared portable toolchain evidence is missing")?;
        admission
            .evidence()
            .verify(&bytes)
            .map_err(|e| e.to_string())?;
        let portable: PortableReview = parse_record(&bytes).map_err(|e| e.to_string())?;
        if portable.subject.release != channel.as_str() || portable.subject.host != request.host {
            continue;
        }
        let id = Path::new(&admission.evidence_record)
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .ok_or("portable review path lacks review ID")?;
        matches.push(digest(id)?);
    }
    let [id] = matches.as_slice() else {
        return Err("exact pinned release/host needs one unambiguous repository admission; explicitly review/accept the selected scope".into());
    };
    Ok(id.clone())
}

pub(crate) fn gate_preflight(
    cli: &Cli,
    current: &Path,
    now: OffsetDateTime,
) -> Result<Option<PathBuf>> {
    let gated = matches!(
        &cli.command,
        Command::Verify
            | Command::Gatehouse {
                command: GatehouseCommand::PreRelease | GatehouseCommand::PolicyCheck
            }
            | Command::Toolchain {
                command: ToolchainCommand::Check
            }
    );
    if !gated {
        if cli.repo.is_some() || cli.data_dir.is_some() || cli.cache_dir.is_some() {
            return Err("toolchain storage/context flags apply only to toolchain commands and verify/release gates".into());
        }
        return Ok(None);
    }
    let repo = repo::discover(current, cli.repo.as_deref())?;
    let Some(repo) = repo else {
        return Ok(None);
    };
    if !repo.config.toolchain.require_admission {
        return Ok(Some(repo.root));
    }
    let home = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")))
        .ok_or("cannot locate user Rustup installation")?;
    let pinned_slot = repo::read_optional(&repo.root, Path::new("rust-toolchain.toml"))?
        .map(|pin| {
            let (channel, request) = barbican::rust_distribution::parse_repository_selection(
                std::str::from_utf8(&pin).map_err(|e| e.to_string())?,
                &default_host(),
                Encoding::Xz,
            )
            .map_err(|e| e.to_string())?;
            Ok::<_, String>(format!("{}-{}", channel.as_str(), request.host))
        })
        .transpose()?;
    super::paths::validate_native_selection(&repo.root, &home, pinned_slot.as_deref())?;
    let stores = Stores::open(
        current,
        Some(&repo.root),
        cli.data_dir.as_deref(),
        cli.cache_dir.as_deref(),
    )?;
    let id = repo_review_id(&repo)?;
    let context = AcceptedContext::load(
        &stores.data,
        id,
        Some(repo.clone()),
        review::policy(Some(&repo), None),
        FreshnessRequest::Local,
        now.unix_timestamp(),
    )?;
    let pin = repo::read_optional(&repo.root, Path::new("rust-toolchain.toml"))?
        .ok_or("canonical pin missing")?;
    let (_, request) = barbican::rust_distribution::parse_repository_selection(
        std::str::from_utf8(&pin).map_err(|e| e.to_string())?,
        &default_host(),
        Encoding::Xz,
    )
    .map_err(|e| e.to_string())?;
    let manifest = barbican::rust_distribution::Manifest::parse(
        &context.review.manifest_bytes,
        &context.review.subject.record().release,
    )
    .map_err(|e| e.to_string())?;
    let required = manifest.select(&request).map_err(|e| e.to_string())?;
    if required
        .archives
        .iter()
        .any(|archive| !context.review.selection.archives.contains(archive))
    {
        return Err(
            "admitted selection does not cover current repository profile/components/targets"
                .into(),
        );
    }
    context.continuing_check(&home, now.unix_timestamp())?;
    let accepted_slot = format!(
        "{}-{}",
        context.review.subject.record().release,
        context.review.subject.record().host
    );
    if pinned_slot.as_deref() != Some(accepted_slot.as_str()) {
        return Err("current pin differs from accepted installed slot".into());
    }
    super::paths::validate_native_selection(&repo.root, &home, Some(&accepted_slot))?;
    repo.recheck()?;
    Ok(Some(repo.root))
}
