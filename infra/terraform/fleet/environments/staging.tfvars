environment = "staging"

coordinator_url = "https://staging-rp2-coordinator.shieldbattery.net"

# Staging soaks the unpromoted tip of main, so it tracks the moving `latest` tag
# rather than the promoted `stable` tag prod uses. Each fresh task launch pulls
# whatever `latest` currently points at.
relay_image_tag = "latest"

# Sized by measurement, not CPU need: small Fargate classes carry small
# network/connection-tracking allowances, and past them a relay silently drops
# QUIC handshakes and turn datagrams while its CPU sits far from saturated.
# Measured on ARM64: 0.25 vCPU degrades near 100 connected players, 0.5 vCPU
# near 300; 1 vCPU served 600 cleanly. The failure mode is silent packet loss
# into live games, so the size stays a step above expected per-relay load.
task_cpu    = 1024
task_memory = 2048

# The publish workflow ships the relay image multi-arch, and Graviton runs
# ~20% cheaper per vCPU-hour than x86 at Fargate's on-demand rates.
cpu_architecture = "ARM64"
