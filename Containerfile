# Single image, single binary, many subcommands.

# The syft stage's source image, overridable at build time. The default is
# the Red Hat GA package from registry.access.redhat.com, which is
# anonymous: no registry credentials are needed to build this image.
# Digest-pinned; the :1 tag moves, so upgrades are deliberate digest bumps.
# To use a different source:
#
#   --build-arg SYFT_IMAGE=docker.io/anchore/syft@sha256:... --build-arg SYFT_BIN=/syft
ARG SYFT_IMAGE=registry.access.redhat.com/hi/syft@sha256:5b3d877d86564897888a31dc368abc3ff511406f8d75ada11f2e02bc1fd011be

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


# Tools target: the binary plus buildah and syft, for the image build and
# SBOM steps. The default stage at the bottom stays the slim micro image,
# so a step that only runs logic never pulls buildah in.
#
# Root on purpose: buildah needs root plus the SETFCAP capability the
# task's securityContext grants, and the CA-bundle setup writes under
# /etc/pki. The micro stage below keeps USER 1001 for everything else.
#
# ubi10, not ubi9: the Red Hat syft package is built against a RHEL 10
# glibc and refuses to run on RHEL 9's.
FROM registry.access.redhat.com/ubi10/ubi-minimal:latest AS tools-base

# buildah and the CA trust tooling from the distro repo; versions follow
# the ubi10 release.
RUN microdnf install -y buildah ca-certificates p11-kit-trust \
    && microdnf clean all

# syft, from the image selected by SYFT_IMAGE at the top of this file.
FROM ${SYFT_IMAGE} AS syft

FROM tools-base AS tools
# The binary sits at /usr/bin/syft in the Red Hat image and /syft in the
# public upstream one; SYFT_BIN points the copy at whichever source is in use.
ARG SYFT_BIN=/usr/bin/syft
COPY --from=syft ${SYFT_BIN} /usr/bin/syft
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
