environment = "staging"

coordinator_url = "https://staging-rp2-coordinator.shieldbattery.net"

# Staging soaks the unpromoted tip of main, so it tracks the moving `latest` tag
# rather than the promoted `stable` tag prod uses. Each fresh task launch pulls
# whatever `latest` currently points at.
relay_image_tag = "latest"
