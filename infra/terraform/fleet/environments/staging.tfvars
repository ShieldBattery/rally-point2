environment = "staging"

coordinator_url = "https://staging-rp2-coordinator.shieldbattery.net"

# Staging soaks the unpromoted tip of main, so it tracks the moving `latest` tag
# rather than the promoted `stable` tag prod uses. Each fresh task launch pulls
# whatever `latest` currently points at.
relay_image_tag = "latest"

# Sized above the smallest Fargate class: 0.25-vCPU tasks carry the smallest
# network/connection-tracking allowances, which silently dropped QUIC handshakes
# and turn datagrams at a few hundred concurrent players before the relay itself
# was anywhere near CPU-bound.
task_cpu    = 1024
task_memory = 2048

# The publish workflow ships the relay image multi-arch, and Graviton runs
# ~20% cheaper per vCPU-hour than x86 at Fargate's on-demand rates.
cpu_architecture = "ARM64"
