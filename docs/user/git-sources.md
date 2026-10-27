# Reviewed Git Sources

Barbican admits a Git dependency only through an exact reviewed repository and
commit. Cargo resolves the graph; `pin add` scaffolds its policy;
`pin check` enforces it before `verify` executes dependency code.
Each locked Git package needs its own reviewed entry, including packages
reached through paths inside the upstream repository.

## Review and admit a source

1. Prepare a disposable Cargo consumer with the intended package, features,
   repository and full lower-case 40-hex `rev`. Resolve its lockfile and collect
   `cargo metadata --format-version 1` without building candidate code. Review
   the immutable upstream source, wrapper/native children, licences, provenance,
   build scripts, proc macros and auxiliary inputs such as submodules, LFS or
   downloaded native code. Retain that evidence in the consumer's review record.
2. Add the reviewed declaration to the real consumer and use `cargo barbican
   resolve`. Compare the actual graph and complete lockfile delta, including
   registry packages and their existing release-age requirements.
3. Run `cargo barbican pin add <package>` for each Git package. The command is
   offline and derives source identity from Cargo.lock. Complete each generated
   review record and remove its pending marker. Separate families can share a
   deliberate review record; consolidating targets into one family is a manual
   policy edit reviewed with that record.
4. Declare source-bound `allowed_surfaces` where the reviewed package requires
   `build-rs`, `proc-macro` or `native-sys`. Review cargo-deny's repository
   permission separately in the consumer's `deny.toml`. Barbican never grants
   that permission or changes unknown-source defaults.
5. Run `inventory --enforce`, `pin check`, `audit` and the normal
   `gatehouse pre-release` workflow. A new source, revision or locked package
   requires re-review. The direct inventory floor can pass while an unreviewed
   Git child still blocks the pin/verification gate.

For example, an exact Git declaration can be renamed:

```toml
[dependencies]
alias = { package = "upstream", git = "https://example.org/team/upstream.git", rev = "0123456789abcdef0123456789abcdef01234567" }
```

Its reviewed family uses the package name:

```toml
[[rust.families]]
name = "upstream-reviewed"
review_record = "docs/dependency-reviews/upstream.md"

[rust.families.direct]
upstream = { source = "git", url = "https://example.org/team/upstream.git", rev = "0123456789abcdef0123456789abcdef01234567" }

[rust.families.resolved]
upstream = { source = "git", version = "0.1.0", url = "https://example.org/team/upstream.git", rev = "0123456789abcdef0123456789abcdef01234567" }
```

These are illustrative identities, not reviewed upstream releases. Git's
package version is retained for consistency; it does not identify a published
registry archive. Git targets never use `checksum_sha256`.

## Exact identity and limits

Use Cargo's emitted repository spelling exactly. Supported URLs are canonical
ASCII `https://host/path` and `ssh://[user@]host/path`, with optional numeric
ports. Hosts are lower-case DNS/IPv4 names; paths use ASCII letters, digits,
`/._~-`, without `.`/`..` or empty interior segments. Credentials, query or
fragment fields, percent encoding, Unicode, IPv6, scp shorthand, HTTP and file
URLs are unsupported. Do not encode credentials in paths or SSH usernames.
`.git`, trailing slash, path case and SSH/HTTPS spelling are distinct review
identities. Cargo may require a noncanonical manifest spelling to be rewritten
to the spelling emitted in Cargo.lock.

The locked source must request and resolve the same full commit:
`git+URL?rev=COMMIT#COMMIT`. Abbreviations, symbolic revisions, branches, tags
and default branches remain unsupported even with a precise locked commit.
Effective inherited workspace declarations and renamed dependencies are
checked; unused workspace templates are not active dependencies.

A reviewed name cannot coexist with another Git revision/repository or a
same-name registry/path source. Patch tables and effective Cargo source
overrides retain their existing fail-closed treatment.

`inspect`, `pick`, `update` and `gatehouse candidate` keep their registry
contracts. The manual pre-add review above is the supported Git intake path.
`update crate@version` refuses a selected Git package, including in dry runs;
it cannot be used to select a new Git revision.

## Advisory evidence and assurance

Git advisory and release-age exceptions are unsupported. A commit timestamp
does not establish registry publication age, and a matching package version
does not inherit a registry exception. Reported Git/ambiguous advisory findings
remain blocking and have no `pin exception` path in this release.

Delegates may omit Git packages entirely. A zero-finding audit therefore lists
Git sources and says their advisory coverage is not established. Any reported
registry patched-version ranges are advisory evidence, not proof that a Git
commit contains a fix. Source and native-code review remain necessary.

Source parity does not authenticate an upstream author, verify signatures,
hash cached/materialised build inputs, sandbox Git/Cargo, or certify auxiliary
downloaded bytes. Existing local-tooling/build-input trust boundaries continue
to apply. Alternate registries and mutable external paths have no positive
reviewed admission form in this release.


## Existing Family Management

Use [Reviewed Families](families.md) to discover exact names and shared review
scope before an explicit `pin add --family=<name> <crate>...` extension.
Shared evidence becomes PENDING before policy publication; new members gain
no permissions, and successful diagnostics/no-ops never substitute for gates.
