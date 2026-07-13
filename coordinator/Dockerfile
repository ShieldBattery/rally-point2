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

FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p rally-point-coordinator

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/rally-point-coordinator /usr/local/bin/rally-point-coordinator
ENTRYPOINT ["/usr/local/bin/rally-point-coordinator"]
