# Ratatoskr — label-driven egress gateways for Kubernetes.
SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c

include hack/versions.env

VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
REGISTRY    ?= ghcr.io/skaldhall
TAG         ?= $(VERSION)
PLATFORMS   ?= linux/amd64,linux/arm64
COMPONENTS  := controller webhook agent gateway init
PLUGINS     := $(notdir $(wildcard plugins/upstream/*))
VARIANT     ?= flannel
MESH        ?= none
DEV_TAG     := dev
DEV_CLUSTER  = ratatoskr-$(VARIANT)

GO_LDFLAGS := -s -w -X github.com/skaldhall/ratatoskr/pkg/version.Version=$(VERSION) -X github.com/skaldhall/ratatoskr/pkg/version.Commit=$(COMMIT)

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_.-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n",$$1,$$2}'

##@ Development

.PHONY: bootstrap
bootstrap: ## Install/verify all host tooling and kernel modules (idempotent)
	hack/bootstrap.sh

.PHONY: fmt
fmt: ## gofmt the tree
	gofmt -s -w $$(git ls-files '*.go' 2>/dev/null || find . -name '*.go')

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: lint
lint: ## golangci-lint, shellcheck-style bash syntax check, helm lint
	golangci-lint run ./...
	for f in hack/*.sh test/e2e/*/*.sh; do if [[ -f $$f ]]; then bash -n $$f; fi; done
	@if [[ -f charts/ratatoskr/Chart.yaml ]]; then helm lint charts/ratatoskr; fi

.PHONY: test
test: ## Unit tests (no root, no cluster)
	go test -race -count=1 -coverprofile=cover.out ./...

.PHONY: test-privileged
test-privileged: ## Tests that need root/netns (netlink, nftables, BPF_PROG_TEST_RUN)
	sudo -E env "PATH=$$PATH" go test -count=1 -tags privileged ./pkg/...

.PHONY: build
build: ## Build all binaries into bin/
	@mkdir -p bin
	for c in $(COMPONENTS); do CGO_ENABLED=0 go build -trimpath -ldflags "$(GO_LDFLAGS)" -o bin/ratatoskr-$$c ./cmd/$$c; done

##@ Images

.PHONY: images
images: ## Build all images for the local platform (loaded into docker)
	for c in $(COMPONENTS); do \
	  docker buildx build --load --build-arg COMPONENT=$$c --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
	    -t $(REGISTRY)/ratatoskr-$$c:$(TAG) . ; \
	done
	for p in $(PLUGINS); do \
	  if [[ -f plugins/upstream/$$p/Dockerfile ]]; then \
	    docker buildx build --load -f plugins/upstream/$$p/Dockerfile --build-arg VERSION=$(VERSION) \
	      -t $(REGISTRY)/ratatoskr-upstream-$$p:$(TAG) . ; \
	  fi; \
	done

.PHONY: images-multiarch
images-multiarch: ## Build multi-arch images (no push; set PUSH=1 to push)
	for c in $(COMPONENTS); do \
	  docker buildx build --platform $(PLATFORMS) $(if $(PUSH),--push,) --build-arg COMPONENT=$$c \
	    --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(REGISTRY)/ratatoskr-$$c:$(TAG) . ; \
	done

##@ Local k3d environment

.PHONY: dev-up
dev-up: ## Create the k3d cluster (VARIANT=flannel|cilium|cilium-wg|calico, MESH=none|sidecar|ambient)
	hack/k3d-up.sh $(VARIANT) --mesh=$(MESH)

.PHONY: dev-down
dev-down: ## Delete the k3d cluster
	hack/k3d-down.sh $(VARIANT)

.PHONY: dev-images
dev-images: ## Build images with the dev tag and import them into the k3d cluster
	$(MAKE) images TAG=$(DEV_TAG)
	k3d image import -c $(DEV_CLUSTER) -m direct \
	  $(foreach c,$(COMPONENTS),$(REGISTRY)/ratatoskr-$(c):$(DEV_TAG)) \
	  $(foreach p,$(PLUGINS),$(if $(wildcard plugins/upstream/$(p)/Dockerfile),$(REGISTRY)/ratatoskr-upstream-$(p):$(DEV_TAG)))

.PHONY: dev-deploy
dev-deploy: dev-images ## Build, import and helm-install the chart into the k3d cluster
	helm upgrade --install ratatoskr charts/ratatoskr -n ratatoskr-system --create-namespace \
	  --kube-context k3d-$(DEV_CLUSTER) -f hack/dev-values.yaml --wait --timeout 5m

##@ End-to-end

.PHONY: e2e
e2e: ## CI-tier e2e (fake upstream, no internet, no secrets)
	VARIANT=$(VARIANT) MESH=$(MESH) test/e2e/ci/run.sh

.PHONY: e2e-live
e2e-live: ## Live-tier e2e (real OpenVPN + ipinfo.io); needs RATATOSKR_E2E_OVPN
	VARIANT=$(VARIANT) MESH=$(MESH) test/e2e/live/run.sh

.PHONY: clean
clean:
	rm -rf bin cover.out
