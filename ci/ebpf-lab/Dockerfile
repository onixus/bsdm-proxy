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
