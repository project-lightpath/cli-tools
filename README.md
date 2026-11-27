# tssc-cli-tools

Supply-chain security tools for the [tssc-validated-pattern][pattern] pipelines,
built as one Go binary in one container image.

[pattern]: https://github.com/project-lightpath/tssc-validated-pattern

## Layout

```
cmd/tssc/            single entrypoint
internal/
  cli/               subcommand wiring, flag surface, env fallbacks
  imagebuild/        buildah invocation marshalling (tssc image build)
  imageref/          image-reference syntax shared by the subcommands
  maven/             pom parsing for tssc bump maven
  sbom/              syft runs and CycloneDX merging (tssc sbom ...)
  tekton/            result files, CA bundle
  version/           build metadata stamped in by the linker
chart/tssc-tasks/    Helm chart: thin Task wrappers that exec the binary
```

The image also installs busybox-style symlinks, so a Task can call
`rhtpa-analyze` instead of `tssc rhtpa analyze`. See
`internal/cli/root.go:argv0Aliases`.

## Conventions

- Every flag also accepts an environment variable (e.g. `--component` /
  `COMPONENT_NAME`); flags win when both are set. The mapping is declared
  per command.
- Tekton results are written to `/tekton/results` when it exists, and
  skipped otherwise.
- Task wrappers map params to flags and nothing else — no `script:` blocks.
  They live as chart templates in `chart/tssc-tasks/`, one source of truth,
  rather than as loose YAML next to a separate chart copy.

## Published image

`quay.io/project-lightpath/tssc-cli-tools`, built for `linux/amd64` and
`linux/arm64`. CI publishes on every merge to `main` and on `v*` tags. Release
tags must use the `vMAJOR.MINOR.PATCH` form, such as `v1.2.3`:

| tag | meaning |
|---|---|
| `sha-<full-commit>-run-<run-id>-<attempt>` | one workflow attempt for a commit; unique across reruns and release events |
| `latest` | newest `main` commit whose serialized promotion passed the freshness check |
| `vX.Y.Z` | release tag for a `vMAJOR.MINOR.PATCH` push |
| `tools-*` | the tools variant (buildah + syft) the Tekton build and SBOM steps run; same tags with a `tools-` prefix |

Pin by digest in a Tekton Task rather than by tag — the digests of both
variants are printed in the publish job's summary:

```yaml
# logic-only steps:
image: quay.io/project-lightpath/tssc-cli-tools@sha256:...
# build and SBOM steps (what the tssc-tasks chart pins):
image: quay.io/project-lightpath/tssc-cli-tools@sha256:...
```

The tools variant's syft comes from the Red Hat GA package on
`registry.access.redhat.com` (`hi/syft`, component hummingbird), pinned by
digest; that registry is anonymous, so builds need no registry credentials
beyond the Quay push secret. Override `SYFT_IMAGE`/`SYFT_BIN` build args to
use a different source (see the Containerfile).

## Published chart

The Task wrappers ship as the [`tssc-tasks`][chart] Helm chart, published as
an OCI artifact to `quay.io/project-lightpath/tssc-tasks` on `v*` tags,
versioned in lockstep with the image (CI refuses a release whose tag does not
match `Chart.yaml`). Consume it pinned by version, e.g.:

    helm pull oci://quay.io/project-lightpath/tssc-tasks --version 0.1.0

See `chart/tssc-tasks/README.md` for the values (the task image reference and
its digest pin).

[chart]: chart/tssc-tasks/

## Development

```
make            # tidy, vet, test, build
make test       # go test ./... -race
make image      # podman build
make image-tools # podman build --target tools (buildah + syft variant)
```
