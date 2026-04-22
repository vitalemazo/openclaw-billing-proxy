REGISTRY  ?= 10.0.3.30:5000
IMAGE     ?= openclaw-billing-proxy
VERSION   := $(shell grep "^const VERSION" proxy.js | sed "s/.*'\(.*\)'.*/\1/")
FULL_TAG  := $(REGISTRY)/$(IMAGE):$(VERSION)
LATEST    := $(REGISTRY)/$(IMAGE):latest
PLATFORM  ?= linux/arm64

.PHONY: build push release version

version:
	@echo "$(VERSION)"

# Uses docker buildx (QEMU cross-compile) so an amd64 build host
# produces an arm64 image for k3s on DGX. Plain `docker build` would
# use the host arch — the node:18-alpine base starts, then the runtime
# fails with `exec /usr/local/bin/docker-entrypoint.sh: exec format
# error` on arm64. Kept consistent with the Python services' Makefiles.
build:
	docker buildx build --platform $(PLATFORM) -t $(FULL_TAG) -t $(LATEST) .

push:
	docker buildx build --platform $(PLATFORM) -t $(FULL_TAG) -t $(LATEST) --push .
	@echo ""
	@echo "Pushed:"
	@echo "  $(FULL_TAG)"
	@echo "  $(LATEST)"

release: push
	@echo ""
	@echo "To deploy in k3s:"
	@echo "  Update image tag in workloads/llm-proxy/deployment.yaml"
	@echo "  git commit + push to dgx-spark-gitops"
	@echo "  ArgoCD auto-syncs"
