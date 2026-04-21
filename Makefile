REGISTRY  ?= 10.0.3.30:5000
IMAGE     ?= openclaw-billing-proxy
VERSION   := $(shell grep "^const VERSION" proxy.js | sed "s/.*'\(.*\)'.*/\1/")
FULL_TAG  := $(REGISTRY)/$(IMAGE):$(VERSION)
LATEST    := $(REGISTRY)/$(IMAGE):latest

.PHONY: build push tag-latest release version

version:
	@echo "$(VERSION)"

build:
	docker build -t $(FULL_TAG) .

tag-latest: build
	docker tag $(FULL_TAG) $(LATEST)

push: tag-latest
	docker push $(FULL_TAG)
	docker push $(LATEST)
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
