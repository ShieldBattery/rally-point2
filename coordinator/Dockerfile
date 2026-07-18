# Builds the coordinator into a minimal runtime image.
#
# Build from the REPOSITORY ROOT (the workspace manifest and sibling crates are
# part of the build context):
#
#   docker build -f coordinator/Dockerfile -t rp2-coordinator .
#
# The runtime stage is distroless: no shell, no package manager — just the
# binary, CA roots (outbound HTTPS to AWS/ECS), and tzdata. The SQLite ledger is
# compiled in (rusqlite `bundled`), so there is no runtime libsqlite3
# dependency. Runs as nonroot; mount a writable volume for the ledger and point
# COORDINATOR_RELAY_LEDGER at it.

# Latest stable Rust, but the OS half of the tag stays bookworm on purpose: the
# runtime stage below is distroless cc-debian12 (= bookworm), and the builder's
# glibc must never be newer than the runtime's or the binary fails to start.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p rally-point-coordinator && mkdir /data-skel

FROM gcr.io/distroless/cc-debian12:nonroot
# /data exists in the image owned by the runtime user (nonroot, 65532) so a
# fresh named volume mounted there inherits that ownership — without this,
# Docker creates the volume root-owned and the ledger/ACME cache can't write.
COPY --from=build --chown=65532:65532 /data-skel /data
COPY --from=build /src/target/release/rally-point-coordinator /usr/local/bin/rally-point-coordinator
ENTRYPOINT ["/usr/local/bin/rally-point-coordinator"]
