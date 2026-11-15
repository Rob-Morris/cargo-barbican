use super::*;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub id: &'static str,
    pub pattern: &'static str,
    pub category: &'static str,
}
pub const RULES: [Rule; 10] = [
    Rule {
        id: "process-command-new",
        pattern: "Command::new(",
        category: "process execution",
    },
    Rule {
        id: "process-command-type",
        pattern: "std::process::Command",
        category: "process execution",
    },
    Rule {
        id: "network-tcp-connect",
        pattern: "TcpStream::connect",
        category: "direct network use",
    },
    Rule {
        id: "network-udp-bind",
        pattern: "UdpSocket::bind",
        category: "direct network use",
    },
    Rule {
        id: "http-reqwest-blocking",
        pattern: "reqwest::blocking::",
        category: "HTTP client use",
    },
    Rule {
        id: "http-reqwest-client",
        pattern: "reqwest::Client",
        category: "HTTP client use",
    },
    Rule {
        id: "http-ureq-get",
        pattern: "ureq::get(",
        category: "HTTP client use",
    },
    Rule {
        id: "http-ureq-post",
        pattern: "ureq::post(",
        category: "HTTP client use",
    },
    Rule {
        id: "shell-curl",
        pattern: "curl ",
        category: "shell downloader token",
    },
    Rule {
        id: "shell-wget",
        pattern: "wget ",
        category: "shell downloader token",
    },
];
pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}
pub fn is_native_source_path(path: &str) -> bool {
    !is_excluded_path(path)
        && std::path::Path::new(path)
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| {
                matches!(
                    s,
                    "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "s" | "S" | "asm"
                )
            })
}
pub fn is_excluded_path(path: &str) -> bool {
    path.starts_with("tests/") || path.starts_with("examples/") || path.starts_with("benches/")
}
#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub package_prefix: String,
    pub required_paths: BTreeSet<String>,
    pub explicit_paths: Option<BTreeSet<String>>,
    pub build_script_paths: BTreeSet<String>,
    pub proc_macro: bool,
    pub native_sys: bool,
    pub package_links: bool,
    pub native_source_paths: BTreeSet<String>,
}
impl Scope {
    pub fn includes(&self, path: &str) -> bool {
        if self.required_paths.contains(path) {
            return true;
        }
        if let Some(paths) = &self.explicit_paths {
            return paths.contains(path);
        }
        self.build_script_paths.contains(path)
            || self.native_source_paths.contains(path)
            || (self.has_execution_surface()
                && path
                    .strip_prefix(&self.package_prefix)
                    .is_some_and(|relative| {
                        !is_excluded_path(relative)
                            && (relative.ends_with(".rs") || is_native_source_path(relative))
                    }))
    }
    pub fn has_execution_surface(&self) -> bool {
        !self.build_script_paths.is_empty()
            || self.proc_macro
            || self.package_links
            || self.native_sys
            || !self.native_source_paths.is_empty()
    }
}
#[derive(Debug, Default)]
pub struct ScanBudget {
    occurrences: usize,
    findings: usize,
    report_bytes: usize,
}
impl ScanBudget {
    fn finding(&mut self, path: &str) -> Result<(), String> {
        self.charge_report(512 + path.len() * 6)?;
        if self.findings >= MAX_FINDINGS {
            return Err("IOC finding budget exceeded".into());
        }
        self.findings += 1;
        Ok(())
    }
    fn occurrence(&mut self) -> Result<(), String> {
        if self.occurrences >= MAX_OCCURRENCES {
            return Err("IOC occurrence budget exceeded".into());
        }
        self.charge_report(MAX_SNIPPET_BYTES * 6 + 96)?;
        self.occurrences += 1;
        Ok(())
    }
    pub fn charge_report(&mut self, bytes: usize) -> Result<(), String> {
        let total = self
            .report_bytes
            .checked_add(bytes)
            .ok_or("IOC report budget overflow")?;
        if total > MAX_REPORT_BYTES - 64 * 1024 {
            return Err("IOC report accumulation budget exceeded".into());
        }
        self.report_bytes = total;
        Ok(())
    }
}
pub struct ScanControl<'a> {
    pub budget: &'a mut ScanBudget,
    pub check: &'a mut dyn FnMut() -> Result<(), String>,
}

pub struct ScanAccumulator {
    inspection: Inspection,
    seen: BTreeSet<String>,
    failure: Option<String>,
}
impl ScanAccumulator {
    pub fn new(source: Source) -> Result<Self, String> {
        let semantics = source.semantics();
        Self::new_with_semantics(source, semantics)
    }
    pub fn new_with_semantics(source: Source, semantics: &str) -> Result<Self, String> {
        source.validate()?;
        if semantics != source.semantics() {
            return Err("IOC source and scope semantics mismatch".into());
        }
        Ok(Self {
            inspection: Inspection {
                source,
                semantics: semantics.into(),
                coverage: Coverage::Complete,
                findings: vec![],
                input_files: 0,
                input_bytes: 0,
                scanned_files: 0,
                scanned_bytes: 0,
            },
            seen: BTreeSet::new(),
            failure: None,
        })
    }
    pub fn scan_file(
        &mut self,
        path: &str,
        bytes: &[u8],
        scope: &Scope,
        budget: &mut ScanBudget,
    ) -> Result<(), String> {
        self.scan_file_checked(path, bytes, scope, budget, &mut || Ok(()))
    }
    pub fn scan_file_checked(
        &mut self,
        path: &str,
        bytes: &[u8],
        scope: &Scope,
        budget: &mut ScanBudget,
        check: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        let result = self.scan_file_inner(path, bytes, scope, budget, check);
        if let Err(error) = &result {
            self.failure = Some(error.clone());
        }
        result
    }
    fn scan_file_inner(
        &mut self,
        path: &str,
        bytes: &[u8],
        scope: &Scope,
        budget: &mut ScanBudget,
        check: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        relative_path(path)?;
        if bytes.len() > 128 * 1024 * 1024
            || self.inspection.input_files >= 100_000
            || self.inspection.input_bytes + bytes.len() as u64 > 1024 * 1024 * 1024
        {
            return Err("IOC source input budget exceeded".into());
        }
        if !self.seen.insert(path.into()) {
            return Err("duplicate IOC file".into());
        }
        self.inspection.input_files += 1;
        self.inspection.input_bytes += bytes.len() as u64;
        if !scope.includes(path) {
            return Ok(());
        }
        self.inspection.scanned_files += 1;
        self.inspection.scanned_bytes += bytes.len() as u64;
        let source_id = self.inspection.source.id()?;
        let file_sha256 = digest_checked(bytes, check)?;
        for rule in &RULES {
            let mut index = None;
            for (start, window) in bytes.windows(rule.pattern.len()).enumerate() {
                if start % (64 * 1024) == 0 {
                    check()?;
                }
                if window != rule.pattern.as_bytes() {
                    continue;
                }
                if index.is_none() {
                    budget.finding(path)?;
                    self.inspection.findings.push(Finding {
                        complete: false,
                        source_id: source_id.clone(),
                        path: path.into(),
                        file_sha256: file_sha256.clone(),
                        rule: rule.id.into(),
                        semantics: self.inspection.semantics.clone(),
                        occurrences: vec![],
                    });
                    index = Some(self.inspection.findings.len() - 1);
                }
                budget.occurrence()?;
                let end = start + rule.pattern.len();
                let snippet_start = start.saturating_sub(40);
                let snippet_end = (end + 40)
                    .min(bytes.len())
                    .min(snippet_start + MAX_SNIPPET_BYTES);
                let snippet = bytes[snippet_start..snippet_end]
                    .iter()
                    .flat_map(|byte| std::ascii::escape_default(*byte))
                    .map(char::from)
                    .collect();
                self.inspection.findings[index.expect("finding inserted")]
                    .occurrences
                    .push(Occurrence {
                        start: start as u64,
                        end: end as u64,
                        snippet,
                    });
            }
            if let Some(index) = index {
                self.inspection.findings[index].complete = true;
            }
        }
        Ok(())
    }
    pub fn finish(mut self, failure: Option<String>) -> Inspection {
        if let Some(reason) = self.failure.or(failure) {
            self.inspection.coverage = Coverage::Incomplete { reason };
            self.inspection
                .findings
                .retain(|finding| !finding.occurrences.is_empty());
        }
        self.inspection.findings.sort();
        self.inspection
    }
}
