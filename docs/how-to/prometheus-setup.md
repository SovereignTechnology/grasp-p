# Prometheus and Grafana Setup

This guide shows how to configure Prometheus and Grafana to monitor ngit-grasp.

## Prerequisites

- ngit-grasp running with metrics enabled (default: `--metrics-enabled true`)
- Prometheus server
- Grafana (optional, for dashboards)

## Verify Metrics Endpoint

First, verify that ngit-grasp is exposing metrics:

```bash
curl http://localhost:7334/metrics
```

You should see Prometheus-formatted metrics like:

```
# HELP ngit_websocket_connections_active Current active WebSocket connections
# TYPE ngit_websocket_connections_active gauge
ngit_websocket_connections_active 5

# HELP ngit_git_operations_total Git operations by type and status
# TYPE ngit_git_operations_total counter
ngit_git_operations_total{operation="clone",status="success"} 42
```

## NixOS Configuration

### Prometheus

Add ngit-grasp as a scrape target:

```nix
services.prometheus = {
  enable = true;
  scrapeConfigs = [
    {
      job_name = "ngit-grasp";
      static_configs = [{
        targets = [ "localhost:7334" ];  # ngit-grasp bind address
      }];
      scrape_interval = "15s";
      metrics_path = "/metrics";
    }
  ];
};
```

### Grafana with Prometheus Datasource

```nix
services.grafana = {
  enable = true;
  settings.server.http_port = 3000;
  
  provision.datasources.settings.datasources = [{
    name = "Prometheus";
    type = "prometheus";
    url = "http://localhost:9090";
    isDefault = true;
  }];
  
  # Optional: provision the ngit-grasp dashboard
  provision.dashboards.settings.providers = [{
    name = "ngit-grasp";
    options.path = "/path/to/ngit-grasp/docs/grafana";
  }];
};
```

## Docker Compose Configuration

For non-NixOS deployments:

```yaml
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
    
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - ./docs/grafana:/var/lib/grafana/dashboards
    environment:
      - GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/var/lib/grafana/dashboards/ngit-grasp-dashboard.json
```

With `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'ngit-grasp'
    static_configs:
      - targets: ['host.docker.internal:7334']  # or your ngit-grasp host
    metrics_path: /metrics
```

## Import Dashboard

1. Open Grafana at `http://localhost:3000`
2. Go to **Dashboards** → **Import**
3. Upload `docs/grafana/ngit-grasp-dashboard.json`
4. Select your Prometheus datasource
5. Click **Import**

## Key Metrics to Monitor

### Connection Health
- `ngit_websocket_connections_active` - Current active connections
- `ngit_websocket_unique_ips` - Number of unique client IPs
- `ngit_websocket_flagged_abusers` - IPs exceeding connection threshold

### Git Operations
- `ngit_git_operations_total` - Operations by type (clone/fetch/push) and status
- `ngit_git_bytes_total` - Bandwidth by direction (in/out)
- `ngit_git_top_repos_bytes` - Top N repositories by bandwidth

### Nostr Events
- `ngit_events_received_total` - Events received by kind
- `ngit_events_stored_total` - Events successfully stored
- `ngit_events_rejected_total` - Events rejected by reason

### System
- `ngit_uptime_seconds` - Server uptime
- `ngit_build_info` - Version and commit info
- `ngit_repositories_total` - Total hosted repositories

## Example Alerts

GRASP-P (private repos) alert rules ship separately: see `docs/grasp-p/ops/prometheus-alerts.yaml`.

Add to your Prometheus alerting rules:

```yaml
groups:
  - name: ngit-grasp
    rules:
      - alert: HighConnectionCount
        expr: ngit_websocket_connections_active > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High number of WebSocket connections"
          
      - alert: AbusiveIPs
        expr: ngit_websocket_flagged_abusers > 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "{{ $value }} IPs flagged for excessive connections"
          
      - alert: PushAuthorizationFailures
        expr: rate(ngit_git_operations_total{operation="push",status="denied"}[5m]) > 0.1
        for: 5m
        labels:
          severity: info
        annotations:
          summary: "Elevated push authorization failures"
```

## See Also

- [Monitoring Overview](../explanation/monitoring.md) - Architecture and design
- [Configuration Reference](../reference/configuration.md) - All config options