# Single image, single binary, many subcommands.

# --platform=$BUILDPLATFORM pins the builder to the machine doing the build,
# so a multi-arch build cross-compiles instead of running the Go toolchain
# under emulation for the foreign architecture. That is only safe because
# CGO_ENABLED=0 below makes the build a pure cross-compile.
FROM --platform=$BUILDPLATFORM registry.access.redhat.com/ubi9/go-toolset:latest AS build

# TSSC_VERSION, not VERSION: the go-toolset base image exports its own
# ENV VERSION (the Go release), and an env with the same name wins over an
# arg during RUN expansion -- the first published images all reported
# "tssc version 1.27.3" because of it.
ARG TSSC_VERSION=dev
ARG COMMIT=
ARG DATE=
ARG TARGETARCH

WORKDIR /src

# Dependencies first, so a source-only change reuses this layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 so the binary runs on ubi9-micro, which has no libc toolchain.
#
# -buildvcs=false because Go otherwise stamps VCS metadata by shelling out to
# git, and the .git directory copied into the build context is owned by a
# different UID than the build user, so git exits 128 and takes the build with
# it. The version, commit and date are passed in as build args and stamped
# through -ldflags below, so there is nothing to lose here.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -buildvcs=false \
      -ldflags "-s -w \
        -X github.com/project-lightpath/cli-tools/internal/version.Version=${TSSC_VERSION} \
        -X github.com/project-lightpath/cli-tools/internal/version.Commit=${COMMIT} \
        -X github.com/project-lightpath/cli-tools/internal/version.Date=${DATE}" \
      -o /tmp/tssc ./cmd/tssc


# Tools target: the same binary plus the tools the image and SBOM steps
# need (buildah, syft). Build with `--target tools`; the default stage at
# the bottom stays the slim micro image, so a step that only runs logic
# never pulls buildah in. Stage order matters: the last stage is the
# default.
#
# Root on purpose: buildah needs root plus the SETFCAP capability the
# task's securityContext grants, and the CA-bundle setup writes under
# /etc/pki. The micro stage below keeps USER 1001 for everything else.
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest AS tools-base

# buildah and the CA trust tooling from the distro repo; the version is
# pinned by the ubi9 release, one level below the digest pin the demo's
# dedicated buildah image carried.
RUN microdnf install -y buildah ca-certificates p11-kit-trust \
    && microdnf clean all

# syft, digest-pinned to the v1.19.0 multi-arch index. The demo ran the
# Red Hat repackage of the same release (rh-syft-tech-preview/syft-rhel9
# 1.19.0); pulling that registry needs credentials a plain build
# environment does not have, so this stage uses the public upstream image
# instead. Swap the reference back if the team prefers the RH distribution
# and has registry.redhat.com pull access where images are built.
FROM docker.io/anchore/syft@sha256:bc1ae555a43011d23bb011a4f50e175fc9a5984a008a3f8f2d692b211fcacd2a AS syft

FROM tools-base AS tools
COPY --from=syft /syft /usr/bin/syft
COPY --from=build /tmp/tssc /usr/bin/tssc
ENTRYPOINT ["/usr/bin/tssc"]


FROM registry.access.redhat.com/ubi9/ubi-micro:latest

# go-toolset builds as a non-root user, which cannot create a directory at the
# filesystem root, so the binary is written to /tmp rather than /out.
COPY --from=build /tmp/tssc /usr/bin/tssc

# Tekton overrides this, but a non-root default keeps the image usable under a
# restricted SCC and matches what the pipeline's SecurityContext expects.
USER 1001

ENTRYPOINT ["/usr/bin/tssc"]
