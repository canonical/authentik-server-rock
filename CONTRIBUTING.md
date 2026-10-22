# Contributing

## Developing

Please refer to
the [rockcraft](https://canonical-craft-parts.readthedocs-hosted.com/en/latest/reference/index.html)
documentations to learn how to develop a rock.

Please install `pre-commit` hooks to help enforce various validations:

```shell
pre-commit install -t commit-msg
```

## Building and Running Locally

You can build the rock using the following command:

```shell
rockcraft pack -v
```

Assuming the [`skopeo`](https://snapcraft.io/install/skopeo/ubuntu) has been
installed. Import the created rock into Docker:

```shell
sudo /snap/rockcraft/current/bin/skopeo --insecure-policy copy oci-archive:<local-rock-name>.rock docker-daemon:authentik-server:latest
```

Run an Authentik server container using Docker:

```shell
docker run -d \
  --rm \
  --name <container-name> \
  authentik-server:latest
```

## Security Checks

Run the local vulnerability checks before you open a pull request.

Check the Go server dependencies for known vulnerabilities with `govulncheck`:

```shell
make govulncheck
```

After you pack the rock with `rockcraft pack`, scan the rock archive with
[Trivy](https://trivy.dev/):

```shell
make scan-rock
```

To scan a specific rock file, set `ROCK_FILE`:

```shell
make scan-rock ROCK_FILE=authentik-server_2026.5.3_amd64.rock
```

In CI, the `unit-test` job runs `make govulncheck` before the
rock build starts. After the build, the `scan` job scans the image with Trivy
and blocks publication if `HIGH` or `CRITICAL` vulnerabilities with available
fixes exist.

## Upstream Upgrades

Moving the rock to a new authentik release is driven by three pieces:

1. Renovate opens a pull request when upstream publishes a release. Patch
   releases and each release series get their own pull request, because
   upstream only supports upgrading one series at a time. These pull requests
   are never auto-approved or automerged.
2. The `Upstream upgrade` workflow comments on any pull request that changes
   the version in `rockcraft.yaml`. The comment compares the upstream files the
   rock's build depends on (toolchains, package manager, Dockerfile) and any
   manual dependency overrides in `rockcraft.yaml` between the two versions,
   automatically removes overrides that are satisfied by the new upstream
   lockfiles, and adds an LLM's judgement of the upgrade risk.
3. The `Upstream charm upgrade issues` workflow opens an issue on each charm
   repository with the changes to make and the checks to run. It is run by
   hand when the charms are ready to upgrade, and reads the version the charms
   are currently on from `charmcraft.yaml` on the target branch (`main` by
   default). Nothing is filed when the rock publishes, because the rock follows
   upstream more closely than the charms do.

Both workflows delegate to the reusable workflows and shared tooling in
[`canonical/identity-team`](https://github.com/canonical/identity-team/tree/main/tools/upstream-upgrade),
configured for this repository by `.github/upstream-upgrade.yaml`.

The LLM is shown the upstream release notes and build files, `rockcraft.yaml`,
and the files of each charm that decide how it configures and runs authentik.
Those files are listed per charm in `.github/upstream-upgrade.yaml`.

The LLM needs the `OPENROUTER_CI_KEY` or a `GEMINI_API_KEY` repository secret,
and its model can be changed with the `OPENROUTER_MODEL` or `GEMINI_MODEL`
repository variables. Without a key the pull request comment still shows the
build comparison, and the charm issues workflow fails.
