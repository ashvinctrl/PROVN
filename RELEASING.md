# Releasing Provn

## One-time setup

- GitHub repo Settings > Actions > General > Workflow permissions > **Read and write permissions**
- Add repository secret `NPM_TOKEN` to publish `@ashvinctrl/provn` to npm
- Optional: create `ashvinctrl/homebrew-tap` and add repository secret `TAP_GITHUB_TOKEN`

Secret names cannot start with `GITHUB_` — GitHub reserves that prefix and
rejects the name. Both jobs are gated on their secret being non-empty and skip
*silently green* when it is missing, so a typo in a secret name looks like a
successful release that published nothing. Check the job actually ran.

## Release flow

1. Bump versions in `provn-cli/Cargo.toml` and `npm/package.json` — they must
   match the tag, or the release fails the version check
2. Run:
   - `cd provn-cli && cargo test`
   - `cd provn-cli && cargo clippy --all-targets -- -D warnings`
   - `cd provn-cli && cargo fmt --all --check`
3. Update `CHANGELOG.md`
4. Commit changes
5. Tag and push:
   - `git tag -a vX.Y.Z -m "Provn vX.Y.Z"`
   - `git push origin main`
   - `git push origin vX.Y.Z`
6. After the release completes, move the major-version alias so
   `uses: ashvinctrl/Provn@v1` picks up the new release:
   - `git tag -f v1 vX.Y.Z && git push -f origin v1`

## What the workflows do

`release.yml` runs on a `v*` tag and chains four jobs:

- `build` — compiles binaries for 5 targets (Linux x86_64/aarch64, macOS
  x86_64/aarch64, Windows x86_64) and publishes a `.sha256` beside each archive
- `release` — creates the GitHub Release with all archives attached
- `homebrew` — calls `update-homebrew.yml` to rewrite the tap formula
- `publish-npm` — publishes `@ashvinctrl/provn`

`homebrew` is a `needs: release` job rather than a workflow listening for
`release: [published]`. That event is raised by the built-in `GITHUB_TOKEN`, and
GitHub does not start workflows from `GITHUB_TOKEN`-raised events — as a
listener it had zero runs across the project's history. `update-homebrew.yml`
also accepts `workflow_dispatch` with a tag, for re-running it by hand.
