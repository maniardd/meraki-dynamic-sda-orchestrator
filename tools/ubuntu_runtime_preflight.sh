#!/usr/bin/env bash
# Read-only preflight for the SDA orchestrator host. This script does not print
# environment variables, credentials, SSH keys, or configuration file content.

set -u

section() {
  printf '\n[%s]\n' "$1"
}

command_status() {
  if command -v "$1" >/dev/null 2>&1; then
    printf '%-16s installed (%s)\n' "$1" "$(command -v "$1")"
  else
    printf '%-16s not installed\n' "$1"
  fi
}

service_status() {
  local service="$1"
  if command -v systemctl >/dev/null 2>&1; then
    printf '%-16s %s\n' "$service" "$(systemctl is-active "$service" 2>/dev/null || true)"
  fi
}

tcp_check() {
  local label="$1"
  local host="$2"
  local port="$3"
  if timeout 3 bash -c "</dev/tcp/${host}/${port}" >/dev/null 2>&1; then
    printf '%-24s reachable (%s:%s)\n' "$label" "$host" "$port"
  else
    printf '%-24s unreachable (%s:%s)\n' "$label" "$host" "$port"
  fi
}

section "Host"
printf 'timestamp_utc    %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'hostname         %s\n' "$(hostname)"
printf 'kernel           %s\n' "$(uname -sr)"
if [ -r /etc/os-release ]; then
  . /etc/os-release
  printf 'operating_system %s\n' "${PRETTY_NAME:-unknown}"
fi
printf 'cpu_count        %s\n' "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"
if [ -r /proc/meminfo ]; then
  awk '/MemTotal/ {printf "memory_kib       %s\n", $2}' /proc/meminfo
fi
df -h / | awk 'NR == 2 {printf "root_disk        size=%s used=%s available=%s use=%s\n", $2, $3, $4, $5}'

section "Runtime packages"
for command_name in docker podman python3 psql redis-cli curl openssl; do
  command_status "$command_name"
done

section "Services"
for service_name in docker podman postgresql redis-server sda-orchestrator; do
  service_status "$service_name"
done

section "Network summary"
printf 'addresses        %s\n' "$(hostname -I 2>/dev/null || echo unavailable)"
ip -4 route 2>/dev/null || true

section "Fabric execution reachability"
if [ -n "${SDA_BORDER_HOST:-}" ]; then
  tcp_check "Border SSH" "$SDA_BORDER_HOST" "22"
else
  printf 'Border SSH               not configured (set SDA_BORDER_HOST)\n'
fi
if [ -n "${SDA_EDGE_HOST:-}" ]; then
  tcp_check "Edge SSH" "$SDA_EDGE_HOST" "22"
else
  printf 'Edge SSH                 not configured (set SDA_EDGE_HOST)\n'
fi

section "Local orchestrator health"
if command -v curl >/dev/null 2>&1; then
  health_code="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' --max-time 5 http://127.0.0.1:8080/health 2>/dev/null || true)"
  printf 'http://127.0.0.1:8080/health status=%s\n' "${health_code:-unreachable}"
else
  printf 'curl is not installed; local health was not checked\n'
fi

section "Result"
printf 'Preflight complete. Review unreachable targets and inactive services above.\n'
