# 蜂眼 BeeEye — build & local test environment
#
# Quick start (no privileges needed; falls back to simulated capture):
#   make dev
#
# Full local stack with real packet capture (needs root or CAP_NET_RAW):
#   make build && sudo make run
#
# Layout: two independent binaries (program.md F42)
#   bin/BeeEye-agent  :8080  storage + detection + REST + BeeEye-web/dist
#   bin/BeeEye-gui    :8081  live capture + dissection + SSE + BeeEye-gui/dist

SHELL      := /bin/bash
GO         ?= go
CLANG      ?= clang
NVCC       ?= /usr/local/cuda/bin/nvcc
NPM        ?= npm

AGENT_DIR  := BeeEye-agent
BIN        := $(AGENT_DIR)/bin
BPF_DIR    := $(AGENT_DIR)/bpf
CUDA_DIR   := $(AGENT_DIR)/cuda
DATA_DIR   := data

AGENT_PORT ?= 8080
GUI_PORT   ?= 8081
IFACE      ?= lo

# BPF target arch, derived rather than assumed, so this builds on arm64 too.
ARCH       := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

CFLAGS_BPF := -O2 -g -Wall -Wno-missing-declarations -Werror \
              -target bpf -D__TARGET_ARCH_$(ARCH) -mcpu=v3 -I $(BPF_DIR)

.DEFAULT_GOAL := help

# ---------------------------------------------------------------- help

.PHONY: help
help: ## Show this help
	@echo "蜂眼 BeeEye — make targets"
	@echo
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Ports: agent :$(AGENT_PORT)  ·  analyzer :$(GUI_PORT)"

# ---------------------------------------------------------------- kernel side

.PHONY: vmlinux
vmlinux: $(BPF_DIR)/vmlinux.h ## Regenerate vmlinux.h from the running kernel's BTF

$(BPF_DIR)/vmlinux.h:
	@command -v bpftool >/dev/null || { echo "bpftool not found: apt install linux-tools-common linux-tools-$$(uname -r)"; exit 1; }
	@test -r /sys/kernel/btf/vmlinux || { echo "/sys/kernel/btf/vmlinux missing: this kernel has no BTF, CO-RE is unavailable"; exit 1; }
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

.PHONY: bpf
bpf: $(AGENT_DIR)/internal/ebpf/BeeEye.bpf.o $(AGENT_DIR)/internal/tlspeek/BeeEye_tls.bpf.o ## Compile the eBPF kernel programs

$(AGENT_DIR)/internal/ebpf/BeeEye.bpf.o: $(BPF_DIR)/BeeEye.bpf.c $(BPF_DIR)/BeeEye_events.h $(BPF_DIR)/vmlinux.h
	$(CLANG) $(CFLAGS_BPF) -c $(BPF_DIR)/BeeEye.bpf.c -o $(BPF_DIR)/BeeEye.bpf.o
	cp $(BPF_DIR)/BeeEye.bpf.o $@

# The TLS uprobe program (F14). Separate object because it attaches to
# userspace symbols rather than to a NIC, and is loaded only when plaintext
# capture is explicitly switched on.
$(AGENT_DIR)/internal/tlspeek/BeeEye_tls.bpf.o: $(BPF_DIR)/BeeEye_tls.bpf.c $(BPF_DIR)/BeeEye_tls_events.h $(BPF_DIR)/vmlinux.h
	@mkdir -p $(AGENT_DIR)/internal/tlspeek
	$(CLANG) $(CFLAGS_BPF) -c $(BPF_DIR)/BeeEye_tls.bpf.c -o $(BPF_DIR)/BeeEye_tls.bpf.o
	cp $(BPF_DIR)/BeeEye_tls.bpf.o $@

.PHONY: bpf-verify
bpf-verify: bpf ## Load the eBPF program to prove it passes the kernel verifier
	@rm -rf /sys/fs/bpf/BeeEye_verify
	bpftool prog loadall $(BPF_DIR)/BeeEye.bpf.o /sys/fs/bpf/BeeEye_verify type classifier
	@echo "verifier accepted:"; ls /sys/fs/bpf/BeeEye_verify
	@rm -rf /sys/fs/bpf/BeeEye_verify

# ---------------------------------------------------------------- CUDA side

.PHONY: cuda
cuda: $(CUDA_DIR)/libBeeEyeRender.so ## Build the CUDA colour-field renderer

$(CUDA_DIR)/libBeeEyeRender.so: $(CUDA_DIR)/BeeEye_render.cu
	@command -v $(NVCC) >/dev/null || { echo "nvcc not found at $(NVCC) — skip this target; the CPU renderer is used instead"; exit 1; }
	$(NVCC) -O3 -Wno-deprecated-gpu-targets --shared -Xcompiler -fPIC -o $@ $<

# ---------------------------------------------------------------- Go side

.PHONY: build
build: bpf ## Build both binaries (CPU renderer)
	cd $(AGENT_DIR) && $(GO) build -o bin/BeeEye-agent .
	cd $(AGENT_DIR) && $(GO) build -o bin/BeeEye-gui ./cmd/BeeEye-gui
	@ls -la $(BIN)

.PHONY: tlspeek
tlspeek: bpf ## Build the TLS plaintext capture tool (F14; gateway-local only)
	cd $(AGENT_DIR) && $(GO) build -o bin/BeeEye-tlspeek ./cmd/BeeEye-tlspeek
	@echo "built bin/BeeEye-tlspeek — grant caps with:"
	@echo "  sudo setcap cap_bpf,cap_perfmon+ep $(BIN)/BeeEye-tlspeek"
	@echo "then: $(BIN)/BeeEye-tlspeek -list"

.PHONY: pcapmerge
pcapmerge: ## Build the capture+keylog merge tool (F14 phase two: one pcapng file, not two)
	cd $(AGENT_DIR) && $(GO) build -o bin/BeeEye-pcapmerge ./cmd/BeeEye-pcapmerge
	@ls -la $(BIN)/BeeEye-pcapmerge

.PHONY: build-cuda
build-cuda: bpf cuda ## Build the analyzer and the overview agent with the CUDA renderer linked in
	cd $(AGENT_DIR) && CGO_ENABLED=1 $(GO) build -tags cuda -o bin/BeeEye-gui-cuda ./cmd/BeeEye-gui
	cd $(AGENT_DIR) && CGO_ENABLED=1 $(GO) build -tags cuda -o bin/BeeEye-agent-cuda .
	@echo "built bin/BeeEye-gui-cuda — /api/render/info will report backend=cuda"
	@echo "built bin/BeeEye-agent-cuda — /api/render/traffic/info will report backend=cuda"

.PHONY: test
test: bpf ## Run the Go test suite
	cd $(AGENT_DIR) && $(GO) test ./...

.PHONY: test-cuda
test-cuda: bpf cuda ## Run the tests including the CUDA/CPU renderer agreement check
	cd $(AGENT_DIR) && CGO_ENABLED=1 $(GO) test -tags cuda ./...

.PHONY: vet
vet: bpf ## go vet + gofmt check
	cd $(AGENT_DIR) && $(GO) vet ./...
	@out=$$(cd $(AGENT_DIR) && gofmt -l . | grep -v vmlinux.h); \
	  if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

# ---------------------------------------------------------------- frontends

.PHONY: web
web: ## Build the overview UI (BeeEye-web/dist)
	cd BeeEye-web && $(NPM) install --no-fund --no-audit && $(NPM) run build

.PHONY: gui-web
gui-web: ## Build the analyzer UI (BeeEye-gui/dist)
	cd BeeEye-gui && $(NPM) install --no-fund --no-audit && $(NPM) run build

.PHONY: frontends
frontends: web gui-web ## Build both frontends

# ---------------------------------------------------------------- running

.PHONY: run-agent
run-agent: ## Run the agent in the foreground
	@mkdir -p $(DATA_DIR)
	BEEEYE_LISTEN=:$(AGENT_PORT) $(BIN)/BeeEye-agent -config config/config.yaml

.PHONY: run-gui
run-gui: ## Run the analyzer in the foreground (IFACE=lo by default)
	$(BIN)/BeeEye-gui -listen :$(GUI_PORT) -iface $(IFACE)

.PHONY: run
run: ## Run both processes in the background, then tail their logs
	@./scripts/dev.sh start

.PHONY: stop
stop: ## Stop both background processes
	@./scripts/dev.sh stop

.PHONY: status
status: ## Show what is running
	@./scripts/dev.sh status

.PHONY: dev
dev: build ## Build and start the full local test environment
	@./scripts/dev.sh start

.PHONY: smoke
smoke: ## End-to-end check that every endpoint on both services answers
	@./scripts/smoke.sh

# ---------------------------------------------------------------- docker

.PHONY: up
up: ## docker compose up -d
	docker compose up -d --build

.PHONY: down
down: ## docker compose down
	docker compose down

.PHONY: logs
logs: ## Follow container logs
	docker compose logs -f

# ---------------------------------------------------------------- cleanup

.PHONY: clean
clean: ## Remove build artifacts (keeps vmlinux.h and the database)
	rm -rf $(BIN) $(BPF_DIR)/BeeEye.bpf.o $(AGENT_DIR)/internal/ebpf/BeeEye.bpf.o
	rm -rf BeeEye-web/dist BeeEye-gui/dist

.PHONY: distclean
distclean: clean ## Also remove vmlinux.h, node_modules, the CUDA library and the database
	rm -f $(BPF_DIR)/vmlinux.h $(CUDA_DIR)/libBeeEyeRender.so
	rm -rf BeeEye-web/node_modules BeeEye-gui/node_modules $(DATA_DIR)
