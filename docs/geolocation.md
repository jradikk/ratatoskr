# Exit geolocation estimates

Gateway metrics can compare geolocation results for the VPN **exit IP** using
three fixed token-free HTTPS providers via the VPN: FreeIPAPI
(`free.freeipapi.com/api/v1/json/<ip>`), GeoJS
(`get.geojs.io/v1/ip/geo/<ip>.json`), and IPWhois (`ipwho.is/<ip>`).
FreeIPAPI documents a free commercial tier with a 60-requests/minute
allowance. IPWhois documents 1,000 requests/day for its free commercial tier.
GeoJS public-service terms do not promise uptime or a guaranteed rate;
review current policies before relying on it in production.
These are provider estimates, not reliable GPS positions or proof of country
or successful selected-client traffic. Each provider may disagree or change
its database, especially for VPN, hosting and anycast addresses. The dashboard
world map places one point per currently valid provider result; the adjacent
table shows reported country/city and exit IP to help explain disagreement.

## Configuration and privacy

`metrics.geolocation.enabled=true` (default) enables upstream-only lookups
while gateway metrics are enabled. `metrics.geolocation.interval=1m` requests
periodic refreshes; IPWhois enforces **at least 2 minutes per gateway
instance** so one instance stays below 1,000/day (720/day at a steady
2-minute interval), while FreeIPAPI/GeoJS are eligible for the configured
1-minute refresh. Actual availability still depends on provider terms,
rate limits, network reachability and runtime backoff. Limits and terms can change; multiple gateway Pods or users behind
one shared exit IP may exhaust an aggregate provider quota. HTTP 429,
provider outage, invalid response and changed exit IP must yield an unknown
sample, not a fabricated point or a fallback to the Pod's direct network.
There are **no API keys or tokens** in the chart. These outbound requests
expose the VPN public exit IP and request timing to each provider; turn
geolocation off if provider terms, privacy requirements, network policy or
upstream VPN restrictions prohibit these requests:

```yaml
metrics:
  enabled: true
  geolocation:
    enabled: false
    interval: 1m
```

Setting `metrics.enabled=false` also disables the gateway geolocation worker.
Enabling is not a guarantee of network access: vendor endpoints must resolve
and be reachable via the configured upstream tunnel. Never configure a direct
network fallback merely to populate a map.

## Reading the dashboard

Import `dashboards/ratatoskr-overview.json`, select your Prometheus datasource,
and filter namespace, gateway and Pod. The map queries
`ratatoskr_gateway_geolocation_latitude_degrees` and
`ratatoskr_gateway_geolocation_longitude_degrees` for each provider and current
exit IP. It requires `ratatoskr_gateway_geolocation_lookup_success=1` and a last
successful lookup timestamp within 300 seconds; missing/stale/failing
providers are omitted rather than shown at (0,0). A single Gateway may have
several Pod replicas and thus several exit IPs. Compare points or the
`ratatoskr_gateway_geolocation_info{provider,exit_ip,country,city}` table
**within the same namespace/gateway/pod and exit_ip**. The `ratatoskr_gateway_geolocation_distance_meters{provider_a,provider_b,exit_ip}`
chart shows pairwise coordinate disagreement in meters where both provider
samples are available; this is an estimate of disagreement, **not** verified
physical distance or geographic accuracy. An unknown sample is not an indication that egress changed.

Metrics contain public exit IP and bounded coarse geographic labels (country,
city, provider); they must not contain client Pod IPs, VPN credentials, tokens
or profile payloads. Limit dashboard/Prometheus access according to local
privacy policy. Provider quota and commercial terms should be reviewed before
large deployments; these are third-party services outside Ratatoskr control.

## Key-free basemap

The dashboard explicitly uses Grafana's built-in OpenStreetMap basemap
(`osm-standard`), not its configurable default or CARTO. No tile API key is
required. Keep the map's OpenStreetMap attribution visible. The viewer's browser
needs access to the public tile service; ordinary interactive use is subject to
OpenStreetMap's tile usage policy and best-effort availability. For restricted
networks or large deployments, configure an appropriate self-hosted tile source
in Grafana instead. Re-import the dashboard or update its ConfigMap to apply the
basemap change to an existing Grafana installation.
