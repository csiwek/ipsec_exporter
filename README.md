# IPsec Exporter [![CircleCI](https://circleci.com/gh/dennisstritzke/ipsec_exporter/tree/master.svg?style=svg)](https://circleci.com/gh/dennisstritzke/ipsec_exporter/tree/master)
Prometheus exporter for ipsec metrics, written in Go.

This version is a fork from Dennis Stritzke original work.
It's made to accomplish strongswan based VPN user concentrator statistics.

## Quick Start
```
glide install
go test -v $(glide novendor)
go install github.com/dennisstritzke/ipsec_exporter
```

## Functionality
The IPsec exporter is determining the state of the configured IPsec tunnels via the following procedure.
1. Starting up the `ipsec.conf` is read. All tunnels configured via the `conn` keyword are observed.
   * Authentication methods are matched for EAP or XAuth. If this methods are found in the conn config, the tunnel will be treated as a multiuser tunnel.
      Metrics are then collected per user also, and the user name is exported under the label "user".
   * If the previous authentication methods are not found, tunnel is treated like in the original version, is treated as a standard point 2 point tunnel, and no user information         is collected.
   
2. If the `/metrics` endpoint is queried, the exporter calls `ipsec status <tunnel name>` for each configured
connection. The output is parsed.
    * If the output contains `ESTABLISHED`, we assume that only the connection is up.
    * If the output contains `INSTALLED`, we assume that the tunnel is up and running.
    * If the output contains `no match`, we assume that the connection is down.

## Value Definition
| Metric | Value | Description |
|--------|-------|-------------|
| ipsec_tunnel_status | 0 | The connection is established and tunnel is installed. The tunnel is up and running. |
| ipsec_tunnel_status | 1 | The connection is established, but the tunnel is not up. |
| ipsec_tunnel_status | 2 | The tunnel is down. |
| ipsec_tunnel_status | 3 | The tunnel is in an unknown state. |
| ipsec_tunnel_status | 4 | The tunnel is ignored. |
