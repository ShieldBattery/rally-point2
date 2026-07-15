environment = "prod"

coordinator_url = "https://CHANGEME-rp2-coordinator.shieldbattery.net"

# Production runs only promoted images: `stable` is moved onto a tested SHA by the
# promote workflow, and each fresh task launch picks it up with no task-def churn.
relay_image_tag = "stable"
