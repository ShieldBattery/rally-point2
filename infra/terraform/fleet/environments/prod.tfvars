environment = "prod"

coordinator_url = "https://CHANGEME-rp2-coordinator.shieldbattery.net"

# Production runs only promoted images: `stable` is moved onto a tested SHA by the
# promote workflow, and each fresh task launch picks it up with no task-def churn.
relay_image_tag = "stable"

# Sized by measurement: a 1 vCPU ARM64 task serves ~600 connected players
# cleanly with the knee near 1000-1200; smaller Fargate classes hit their
# network/connection-tracking allowances well before CPU (0.25 vCPU degrades
# near 100 players, 0.5 near 300), and past the allowance the failure mode is
# silent packet loss into live games. ARM64 because the relay image publishes
# multi-arch and Graviton runs ~20% cheaper per vCPU-hour.
task_cpu         = 1024
task_memory      = 2048
cpu_architecture = "ARM64"
