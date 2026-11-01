# Security policy

## Reporting a vulnerability

Please do not include VPN profiles, credentials, private keys, kubeconfigs, or
unredacted packet captures in a public issue.

Use the repository's **Security → Report a vulnerability** option for a private
report if available. If private reporting is unavailable, contact the maintainer
through the contact details on their GitHub profile to arrange a private channel
before sharing exploit details. Do not assume a public issue is confidential.

Include the affected version or commit, deployment mode, runtime/CNI, impact,
and a minimal reproduction with synthetic credentials. No response-time SLA or
long-term support policy is currently promised; use the latest reviewed release
and consult its release notes for security fixes.

## Trust boundaries

- The node agent has host PID/network access and a CRI socket mount. Treat it as
  **node-root-equivalent**, even though its container is not privileged. Only
  trusted administrators should install or modify the operator and its RBAC.
- Gateway and upstream containers have network-administration capabilities.
  Custom upstream images are trusted code in the gateway's shared network
  namespace; review and pin them before deployment.
- Namespace labels used by `allowedNamespaces.namespaceSelector` are access
  controls. Restrict who can change them. A missing selector denies all access;
  an empty selector allows all namespaces.
- Egress exclusions deliberately bypass the VPN. Configure the actual cluster
  ranges and avoid broad exclusions. Cloud metadata is blocked by default.
- `dns.mode: cluster` retains cluster DNS, including its external resolver path.
  Use `dns.mode: gateway` when external DNS must use the VPN.
- `encryption: none` does not encrypt the in-cluster GENEVE leg. Use the optional
  WireGuard layer with the iproute datapath when that leg requires encryption.
- Keep upstream configuration in Kubernetes Secrets, not Helm values or custom
  resources. Protect Secret access and encryption at rest according to your
  cluster's security requirements.

Fail-closed routing protects traffic selected for Ratatoskr; it is not a general
sandbox for applications granted node access or network-administration powers.
Review the [architecture](docs/design.md) and [chart security model](charts/ratatoskr/README.md)
when evaluating whether a deployment meets your threat model.
