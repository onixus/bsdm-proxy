# Toolchain for the eBPF/XDP lab run (ci/ebpf-lab/Jenkinsfile).
#
# One image both builds the proxy and runs it against a real kernel: the lab
# container is started with --privileged --network none, so the XDP program
# lands on a veth pair inside the container's own network namespace and never
# touches the host's NICs.
FROM rust:1-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      clang llvm libbpf-dev bpftool iproute2 iputils-ping curl jq libcap2-bin \
      cmake pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*

# Unprivileged by default: the cargo build runs as `lab` (uid 1000, the Jenkins
# agent's user, so the bind-mounted workspace stays writable). Only the kernel
# smoke opts into root with `docker run --user 0 --privileged`, because loading
# BPF and creating network namespaces needs it. The cache mount points are
# pre-created with `lab` ownership so fresh named volumes inherit it.
RUN useradd --uid 1000 --create-home lab \
 && mkdir -p /usr/local/cargo/registry /target \
 && chown lab:lab /usr/local/cargo/registry /target
USER lab

# One-shot build/test container, not a service: nothing to probe.
HEALTHCHECK NONE
