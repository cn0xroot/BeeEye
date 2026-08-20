# 蜂眼 BeeEye — builds both binaries from one Go module.
#
# The eBPF object is NOT built here. CO-RE needs vmlinux.h generated from the
# BTF of the kernel the program will actually run on, and a container image has
# no access to the host's /sys/kernel/btf at build time. Run `make bpf` on the
# host first; this stage copies the result in.

FROM golang:1.25-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Fail early and legibly rather than producing a binary that panics on start.
RUN test -f internal/ebpf/BeeEye.bpf.o || { \
      echo "internal/ebpf/BeeEye.bpf.o is missing — run 'make bpf' on the host first"; \
      exit 1; }

# CGO off keeps both binaries statically linked. The CUDA renderer is a
# separate, opt-in build (`make build-cuda`) because it needs the CUDA runtime
# present; the CPU renderer produces the same image without it.
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/BeeEye-agent . && \
    go build -trimpath -ldflags="-s -w" -o /out/BeeEye-gui ./cmd/BeeEye-gui

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /out/BeeEye-agent /usr/local/bin/BeeEye-agent
COPY --from=build /out/BeeEye-gui   /usr/local/bin/BeeEye-gui

WORKDIR /app
EXPOSE 8080 8081

CMD ["/usr/local/bin/BeeEye-agent", "-config", "/app/config/config.yaml"]
