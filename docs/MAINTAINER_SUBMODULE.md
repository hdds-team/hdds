# Private Maintainer Submodule

This repository supports private maintainer tooling via a Git submodule mounted at `maintainer/`.

Why:
- Keep operational/release scripts private.
- Keep changes reviewed and versioned with normal Git history.
- Pin each public repo commit to a known maintainer-tooling commit.

## Recommended layout

Use `maintainer/` as a private submodule path.

Example:

```bash
git submodule add git@your.git.host:org/hdds-maintainer.git maintainer
git submodule update --init --recursive maintainer
```

If you currently keep local private scripts in `maintainer/`, move them aside first
(for example `mv maintainer maintainer.local`) before adding the submodule.

## Make targets

- `make maintainer-init`: initialize the private submodule (if configured).
- `make maintainer-update`: update submodule to latest remote commit.
- `make maintainer-status`: show current submodule status, branch, commit.
- `make release-validate`: run `maintainer/validate-release.sh`.

## Team onboarding

After cloning:

```bash
make maintainer-init
```

If access is missing, maintainer targets fail gracefully with a clear message.

## CI and reproducibility

- In CI without private access, skip private gates explicitly.
- In release jobs with private access, log submodule SHA in build evidence.

Suggested command:

```bash
cd maintainer && git rev-parse --short HEAD
```
