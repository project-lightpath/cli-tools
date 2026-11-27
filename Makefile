BINARY  ?= tssc
REGISTRY ?= quay.io/project-lightpath
IMAGE   ?= $(REGISTRY)/tssc-cli-tools

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
  -X github.com/project-lightpath/cli-tools/internal/version.Version=$(VERSION) \
  -X github.com/project-lightpath/cli-tools/internal/version.Commit=$(COMMIT) \
  -X github.com/project-lightpath/cli-tools/internal/version.Date=$(DATE)

.DEFAULT_GOAL := all

.PHONY: all
all: tidy vet test build

.PHONY: build
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/tssc

.PHONY: test
test:
	go test ./... -race -coverprofile=coverage.out

.PHONY: vet
vet:
	go vet ./...

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: lint
lint:
	golangci-lint run

.PHONY: image
image:
	podman build \
	  --build-arg TSSC_VERSION=$(VERSION) \
	  --build-arg COMMIT=$(COMMIT) \
	  --build-arg DATE=$(DATE) \
	  -t $(IMAGE):$(VERSION) -f Containerfile .

# Tekton pulls this image on every TaskRun, so it needs both architectures the
# cluster might schedule onto.
.PHONY: image-multiarch
image-multiarch:
	podman build --platform linux/amd64,linux/arm64 --manifest $(IMAGE):$(VERSION) \
	  --build-arg TSSC_VERSION=$(VERSION) -f Containerfile .

.PHONY: clean
clean:
	rm -rf bin dist coverage.out
