# Maintenance

## Create a release

1. Update version in `Cargo.toml` and run `cargo check`.
2. Set release version and date in CHANGELOG.md and amend the commit from 1.
3. Commit everything
4. `cargo publish`
5. Run `git tag "v<new version>"`
6. `git push && git push --tags`
