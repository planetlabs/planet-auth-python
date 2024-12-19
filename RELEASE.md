# Version Release

*Planet maintainers only*

Releasing consists of publishing new packages to PyPi and ReadTheDocs, and
is automated using Github Workflows and Actions.  Once initiated, the 
release pipeline will automatically take care of building, testing, tagging,
and publishing the release.

## Versions and Stability

This library follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
and therefore only major releases should break compatibility.  Minor versions
may include new functionality, and patch versions address bugs or trivial
changes (like documentation).

## Release Workflow

Releases should generally be published from the main branch, which should be
kept stable.

1. Create a release branch off of `main` that bumps the version number in
   [version.txt](./version.txt), and updates the
   [changelog.md](./docs/changelog.md).
2. Collect all features targeted for the intended release in the branch, and
   create a PR to merge the release branch into `main`.
3. Ensure that all tests are passing on `main` branch after all merges.
4. Determine the type of release that should be performed.  This will be passed
   to the release workflow as the `build-variant` argument:
   * `release` - The final build for a new release version.
   * `rc` - A candidate for the final release.
   * `beta` - A beta release.
   * `alpha` - An alpha release
   * `dev` - A development release.  This is the default.
5. Initiate a release by activating the [Release Orchestration Workflow](./.github/workflows/release-orchestrate.yml) pipeline:
   * The release pipeline may be initiated in the GUI.
   * The release pipeline may be initiated by the `gh` CLI as follows:
     ```bash
     gh workflow run .github/workflows/release-orchestrate.yml -f build-variant=_selected_release_variation_
   * ```

## Local Publishing

Most actions taken by the release pipeline are coded into the [noxfile.py](./noxfile.py),
and so available for local execution.  However, under normal circumstances 
releases should be driven by the CI/CD release pipeline and not performed 
locally.  Local publishing skips the mechanism used to generate unique build
numbers (which is not in the `noxfile.py`), and circumvents audit and review
processes implemented by the CI/CD system and repository configuration.
