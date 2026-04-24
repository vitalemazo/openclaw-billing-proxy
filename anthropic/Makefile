REGISTRY  ?= 10.0.3.30:5000
IMAGE     ?= anthropic-proxy
VERSION   := $(shell grep "^const VERSION" proxy.js | sed "s/.*'\(.*\)'.*/\1/")
FULL_TAG  := $(REGISTRY)/$(IMAGE):$(VERSION)
LATEST    := $(REGISTRY)/$(IMAGE):latest
PLATFORM  ?= linux/arm64

.PHONY: build push version

version:
	@echo "$(VERSION)"

build:
	docker buildx build --platform $(PLATFORM) -t $(FULL_TAG) -t $(LATEST) .

push:
	docker buildx build --platform $(PLATFORM) -t $(FULL_TAG) -t $(LATEST) --push .
	@echo ""
	@echo "Pushed:"
	@echo "  $(FULL_TAG)"
	@echo "  $(LATEST)"
