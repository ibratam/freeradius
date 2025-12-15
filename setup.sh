#!/bin/bash
set -euo pipefail

# File: `setup.sh`
# Installs Docker Engine and Docker Compose (plugin or standalone binary).

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

echo "== Installing prerequisites =="
if command -v apt-get >/dev/null 2>&1; then
  $SUDO apt-get update -y
  $SUDO apt-get install -y ca-certificates curl gnupg lsb-release
elif command -v dnf >/dev/null 2>&1; then
  $SUDO dnf -y install curl
elif command -v yum >/dev/null 2>&1; then
  $SUDO yum -y install curl
fi
run_compose_and_wait() {
  # Detect compose command
  if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
  elif docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  else
    echo "== No docker-compose / docker compose available - skipping compose up =="
    return 0
  fi

  # Find compose file in current directory
  if [ -f docker-compose.yml ] || [ -f docker-compose.yaml ]; then
    echo "== Found compose file, using: $COMPOSE_CMD =="
  else
    echo "== No compose file in $(pwd) - skipping compose up =="
    return 0
  fi

  # Allow override of sudo usage and timeout
  SUDO="${SUDO:-}"
  TIMEOUT="${COMPOSE_UP_TIMEOUT:-300}" # seconds

  # Use a predictable project name (optional)
  export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-$(basename "$(pwd)")}"

  echo "== Starting compose in background =="
  $SUDO $COMPOSE_CMD up -d

  # collect container ids for this project
  IDS=$($SUDO $COMPOSE_CMD ps -q)
  if [ -z "$IDS" ]; then
    echo "== No containers created by compose - nothing to wait for =="
    return 0
  fi

  echo "== Waiting for containers to be healthy/running (timeout ${TIMEOUT}s) =="
  start_ts=$(date +%s)
  deadline=$((start_ts + TIMEOUT))

  while true; do
    all_ok=true
    for id in $IDS; do
      # inspect returns health status if defined, otherwise the state status
      status=$($SUDO docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null || echo "unknown")
      # treat 'healthy' or 'running' as success
      if [ "$status" != "healthy" ] && [ "$status" != "running" ] && [[ "$status" != Up* ]]; then
        all_ok=false
        break
      fi
    done

    if $all_ok; then
      now_ts=$(date +%s)
      elapsed=$((now_ts - start_ts))
      printf "== All containers are up after %d second(s)\n" "$elapsed"
      $SUDO $COMPOSE_CMD ps
      break
    fi

    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "== Timeout after ${TIMEOUT}s waiting for containers"
      $SUDO $COMPOSE_CMD ps
      # show failing containers' inspect for debugging
      for id in $IDS; do
        echo "---- inspect $id ----"
        $SUDO docker inspect --format '{{json .State}}' "$id" 2>/dev/null || true
      done
      return 2
    fi

    sleep 2
  done
}

install_docker_debian() {
  echo "== Installing Docker (Debian/Ubuntu) =="
  $SUDO mkdir -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg | $SUDO gpg --dearmour -o /etc/apt/keyrings/docker.gpg
  . /etc/os-release
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$ID \
    $(lsb_release -cs) stable" | $SUDO tee /etc/apt/sources.list.d/docker.list > /dev/null
  $SUDO apt-get update -y
  $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
}

install_docker_rhel() {
  echo "== Installing Docker (RHEL/CentOS/Fedora) =="
  if command -v dnf >/dev/null 2>&1; then
    $SUDO dnf -y remove docker \
      docker-client \
      docker-client-latest \
      docker-common \
      docker-latest \
      docker-latest-logrotate \
      docker-logrotate \
      docker-engine || true
    $SUDO dnf -y install dnf-plugins-core
    $SUDO dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    $SUDO dnf -y install docker-ce docker-ce-cli containerd.io
  else
    $SUDO yum -y install yum-utils
    $SUDO yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    $SUDO yum -y install docker-ce docker-ce-cli containerd.io
  fi
  # docker-compose-plugin may be available via package repos on some systems
  if command -v dnf >/dev/null 2>&1; then
    $SUDO dnf -y install docker-compose-plugin || true
  fi
}

install_compose_fallback() {
  if command -v docker-compose >/dev/null 2>&1 || docker compose version >/dev/null 2>&1; then
    return 0
  fi

  echo "== Installing docker-compose (standalone binary fallback) =="
  TAG=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  [ -n "$TAG" ] || TAG="v2.20.2"
  ARCH=$(uname -m)
  OSNAME=$(uname -s)
  BIN_URL="https://github.com/docker/compose/releases/download/${TAG}/docker-compose-${OSNAME}-${ARCH}"
  $SUDO curl -L --fail "$BIN_URL" -o /usr/local/bin/docker-compose
  $SUDO chmod +x /usr/local/bin/docker-compose
}

# Main detection/install
if [ -f /etc/os-release ]; then
  . /etc/os-release
  case "$ID" in
    ubuntu|debian)
      install_docker_debian
      ;;
    fedora|centos|rhel)
      install_docker_rhel
      ;;
    *)
      echo "== Unknown ID: $ID - falling back to convenience script =="
      $SUDO curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
      $SUDO sh /tmp/get-docker.sh
      ;;
  esac
else
  echo "== No /etc/os-release - using convenience script =="
  $SUDO curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  $SUDO sh /tmp/get-docker.sh
fi

# Ensure docker service running
if command -v systemctl >/dev/null 2>&1; then
  $SUDO systemctl enable --now docker || true
fi

# Try to install compose plugin via package manager if not present
if ! docker compose version >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get install -y docker-compose-plugin || true
  fi
  if command -v dnf >/dev/null 2>&1; then
    $SUDO dnf -y install docker-compose-plugin || true
  fi
fi

# Final fallback: download standalone compose binary
install_compose_fallback

echo "== Installation complete =="
docker --version || true
if command -v docker-compose >/dev/null 2>&1; then
  docker-compose --version || true
else
  docker compose version || true
fi
run_compose_and_wait
