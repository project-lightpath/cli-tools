# Single image, single binary, many subcommands.

# --platform=$BUILDPLATFORM pins the builder to the machine doing the build,
# so a multi-arch build cross-compiles instead of running the Go toolchain
# under emulation for the foreign architecture. That is only safe because
# CGO_ENABLED=0 below makes the build a pure cross-compile.
FROM --platform=$BUILDPLATFORM registry.access.redhat.com/ubi9/go-toolset:latest AS build

ARG VERSION=dev
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
        -X github.com/project-lightpath/cli-tools/internal/version.Version=${VERSION} \
        -X github.com/project-lightpath/cli-tools/internal/version.Commit=${COMMIT} \
        -X github.com/project-lightpath/cli-tools/internal/version.Date=${DATE}" \
      -o /tmp/tssc ./cmd/tssc


FROM registry.access.redhat.com/ubi9/ubi-micro:latest

# go-toolset builds as a non-root user, which cannot create a directory at the
# filesystem root, so the binary is written to /tmp rather than /out.
COPY --from=build /tmp/tssc /usr/bin/tssc

# Tekton overrides this, but a non-root default keeps the image usable under a
# restricted SCC and matches what the pipeline's SecurityContext expects.
USER 1001

ENTRYPOINT ["/usr/bin/tssc"]
