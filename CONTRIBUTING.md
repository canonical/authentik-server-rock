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

## Upstream Upgrades

Moving the rock to a new authentik release is driven by three pieces:

1. Renovate opens a pull request when upstream publishes a release. Patch
   releases and each release series get their own pull request, because
   upstream only supports upgrading one series at a time. These pull requests
   are never auto-approved or automerged.
2. The `Upstream upgrade` workflow comments on any pull request that changes
   the version in `rockcraft.yaml`. The comment compares the upstream files the
   rock's build depends on (toolchains, package manager, Dockerfile) between
   the two versions, and adds an LLM's judgement of the upgrade risk.
3. When the pull request is merged and the image is published, `ci` opens an
   issue on each charm repository with the changes to make and the checks to
   run. A series bump always opens issues; a patch bump only does when its
   risk is not low.

The LLM needs a `GEMINI_API_KEY` or `OPENROUTER_API_KEY` repository secret, and
its model can be changed with the `GEMINI_MODEL` or `OPENROUTER_MODEL`
repository variables. Without a key the pull request comment still shows the
build comparison, and no charm issues are opened.

To see what the tooling produces for a pair of versions, run it locally. It
writes the pull request comment, and with an API key the charm issues, to
`.artifacts/`:

```shell
python3 scripts/upstream_upgrade.py --from 2026.5.3 --to 2026.8.3
```

The `Upstream charm upgrade issues` workflow can also be run by hand; with its
dry-run input it prints the issues in the run summary instead of opening them.

Run the tooling's tests with:

```shell
python3 -m unittest discover -s tests
```
