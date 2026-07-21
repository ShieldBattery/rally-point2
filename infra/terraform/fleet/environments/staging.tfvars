environment = "staging"

coordinator_url = "https://staging-rp2-coordinator.shieldbattery.net"

# Staging soaks the unpromoted tip of main, so it tracks the moving `latest` tag
# rather than the promoted `stable` tag prod uses. Each fresh task launch pulls
# whatever `latest` currently points at.
relay_image_tag = "latest"

# Half the production size: staging's day-to-day sessions stay below the
# topology-dependent load-test targets for this class. A load-test round that
# needs the production envelope bumps these to match prod.tfvars for the run
# and drops them back afterward.
task_cpu    = 512
task_memory = 1024

# The publish workflow ships the relay image multi-arch, and Graviton runs
# ~20% cheaper per vCPU-hour than x86 at Fargate's on-demand rates.
cpu_architecture = "ARM64"
