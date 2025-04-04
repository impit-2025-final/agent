#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

INSTALL_DIR="/opt/monitoring-agent"
SYSTEMD_DIR="/etc/systemd/system"
DOWNLOAD_URL="https://github.com/impit-2025-final/agent/releases/download/latest/monitoring-agent.tar.gz"
ARCHIVE_PATH="/tmp/monitoring-agent.tar.gz"


UPDATE_MODE=false
if [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/config.yaml" ]; then
  echo "Existing installation detected."
  read -p "Update existing installation? [Y/n]: " UPDATE_CHOICE
  UPDATE_CHOICE=${UPDATE_CHOICE:-Y}
  if [[ $UPDATE_CHOICE =~ ^[Yy]$ ]]; then
    UPDATE_MODE=true
    echo "Updating..."
  else
    echo "GG Update."
  fi
fi

if [ "$UPDATE_MODE" = true ]; then
  echo "Backing..."
  cp "$INSTALL_DIR/config.yaml" "/tmp/monitoring-agent-config.yaml.bak"
fi

echo "Installing agent..."

mkdir -p $INSTALL_DIR

if [ "$UPDATE_MODE" = false ]; then
  DEFAULT_URL="http://localhost:8080"
  read -p "Enter service URL [$DEFAULT_URL]: " SERVICE_URL
  SERVICE_URL=${SERVICE_URL:-$DEFAULT_URL}

  DEFAULT_TOKEN="1234567890"
  read -p "Enter service token [$DEFAULT_TOKEN]: " SERVICE_TOKEN
  SERVICE_TOKEN=${SERVICE_TOKEN:-$DEFAULT_TOKEN}

  echo "Creating config.yaml file"
  cat > $INSTALL_DIR/config.yaml << EOF
service:
  url: "$SERVICE_URL"
  update_interval: 60
  token: "$SERVICE_TOKEN"
docker:
  network: "bridge"
  ignore_containers:
    - "redis"
EOF
fi

echo "Downloading agent from $DOWNLOAD_URL"
curl -L -o $ARCHIVE_PATH $DOWNLOAD_URL


if systemctl is-active --quiet monitoring-agent.service; then
  echo "Stopping running service..."
  systemctl stop monitoring-agent.service
fi

echo "Extracting archive to $INSTALL_DIR"
mkdir -p /tmp/agent-extract
tar -xzf $ARCHIVE_PATH -C /tmp/agent-extract
cp -f /tmp/agent-extract/agent $INSTALL_DIR/
mkdir -p $INSTALL_DIR/bpf
cp -f /tmp/agent-extract/bpf/* $INSTALL_DIR/bpf/
rm -rf /tmp/agent-extract

chmod +x $INSTALL_DIR/agent

if [ ! -f "$SYSTEMD_DIR/monitoring-agent.service" ] || [ "$UPDATE_MODE" = false ]; then
  echo "Creating systemd service"
  cat > $SYSTEMD_DIR/monitoring-agent.service << EOF
[Unit]
Description=Network Traffic Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/agent
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=10
User=root
Group=root
Environment=BPF_DIR=$INSTALL_DIR/bpf
Environment=CONFIG_PATH=$INSTALL_DIR/config.yaml

[Install]
WantedBy=multi-user.target
EOF
fi

echo "Starting service"
systemctl daemon-reload
systemctl enable monitoring-agent.service
systemctl start monitoring-agent.service

if systemctl is-active --quiet monitoring-agent.service; then
  echo "Service status:"
  systemctl status monitoring-agent.service --no-pager
  
  if [ "$UPDATE_MODE" = true ]; then
    echo "Update completed successfully!"
  else
    echo "Installation completed successfully!"
  fi
else
  echo "Failed to start monitoring agent service."
  echo "Check logs with: journalctl -u monitoring-agent.service"
  
  if [ "$UPDATE_MODE" = true ] && [ -f "/tmp/monitoring-agent-config.yaml.bak" ]; then
    echo "Restoring backup configuration..."
    cp "/tmp/monitoring-agent-config.yaml.bak" "$INSTALL_DIR/config.yaml"
  fi
  
  exit 1
fi

echo "Cleaning up"
rm $ARCHIVE_PATH
[ -f "/tmp/monitoring-agent-config.yaml.bak" ] && rm "/tmp/monitoring-agent-config.yaml.bak"

if [ "$UPDATE_MODE" = true ]; then
  echo "Agent updated successfully!"
else
  echo "Agent installed successfully!"
fi