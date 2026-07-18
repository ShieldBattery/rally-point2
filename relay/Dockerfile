# Builds the relay into a minimal runtime image.
#
# Build from the REPOSITORY ROOT (the workspace manifest and sibling crates are
# part of the build context):
#
#   docker build -f relay/Dockerfile -t rp2-relay .
#
# The runtime stage is distroless: no shell, no package manager — just the
# binary, CA roots (outbound WSS to the coordinator), and tzdata. The relay
# writes nothing to disk: its identity (RELAY_ID, RELAY_ENROLL_TOKEN,
# RELAY_REGION, tenant/coordinator settings) arrives entirely via RELAY_* env,
# and when no --cert/--key is supplied it generates a self-signed TLS
# certificate in memory at startup. No volumes, no /data. Runs as nonroot and
# serves QUIC on UDP 14900 (dual-stack, both game clients and peer-relay mesh
# links) plus an outbound WSS control connection to the coordinator.

# Latest stable Rust, but the OS half of the tag stays bookworm on purpose: the
# runtime stage below is distroless cc-debian12 (= bookworm), and the builder's
# glibc must never be newer than the runtime's or the binary fails to start.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p rally-point-relay

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/rally-point-relay /usr/local/bin/rally-point-relay
ENTRYPOINT ["/usr/local/bin/rally-point-relay"]
