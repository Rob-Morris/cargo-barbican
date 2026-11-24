# Hosted token-context fixture data

These files are deployment inputs for the separately approved hosted token
proof. They are not workspace dependencies or installed/executed test tools.
The public rehearsal copies Cargo.toml.fixture to token-proof/Cargo.toml and
lib.rs.fixture to token-proof/src/lib.rs, and merges the bounded Dependabot
entry into .github/dependabot.yml without replacing existing entries.

The deliberately older serde requirement lets Dependabot author a real version
update PR. The current product graph already reviews serde1.0.228; the fixture
need not assess or execute1.0.227 because the proof workflow never builds, installs, extracts or executes any
fixture dependency. Dependabot owns its remote metadata resolution.
The only workflow verifies fixed inert upstream gh bytes with a read-only token.
Do not run Cargo against these files locally or add them to the product graph.

Preserve existing rehearsal files/controller tags. Copy the reviewed standalone
qualify-release-consumer workflow to public/private/fork hosts, and record real
run/actor/fork/visibility witnesses. Public fixture content is harmless authored
data. No release publication, security-setting mutation or private source copy
is authorised merely by the existence of these deployment inputs.
