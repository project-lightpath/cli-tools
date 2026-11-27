# tssc-tasks

Thin Tekton task wrappers around the `tssc` CLI from
[cli-tools](https://github.com/project-lightpath/cli-tools). The tasks carry
no logic and no `script:` blocks — each step maps params to `tssc` flags, so
the behavior is the tested Go code in this repository, not shell in YAML.

Tasks included:

- `buildah-rhtap` — build an image with buildah, push it, generate and merge
  CycloneDX 1.6 SBOMs (source and image). Params and results match the task
  of the same name from tssc-validated-pattern, minus the cosign upload step.

The chart is published as an OCI artifact to
`quay.io/project-lightpath/tssc-tasks` on `v*` tags, versioned in lockstep
with the image (the release workflow checks `Chart.yaml` matches the tag).
Consume it pinned by version, for example with Helm:

    helm upgrade --install tssc-tasks \
      oci://quay.io/project-lightpath/tssc-tasks --version 0.1.0

Or as a chart dependency from the consuming pattern's `Chart.yaml`. The task
image defaults to `quay.io/project-lightpath/tssc-cli-tools:tools-latest`
(the buildah + syft variant); set `image.digest` to pin it to the exact
digest printed in the release job's summary (the digest wins over the tag
when both are set).
