# Workload startup

In agent mode the injected init container waits for the agent's networking
readiness marker. It does not start application containers until the protected
path is installed.

Gateway client configuration is read directly from its owner-validated ConfigMap
through a name-filtered API watch. Mounted ConfigMap propagation is no longer on
the production startup path. Each plaintext gateway has a dedicated ServiceAccount
and a namespaced Role limited to its ConfigMap. WireGuard gateways retain their
shared ServiceAccount, with read access to the gateway ConfigMaps in that namespace.
VPN Secrets remain mounted only into upstream containers.

Healthy gateways awaiting the latest client configuration acknowledgment are
rechecked by the controller every 500 milliseconds. The agent also retries pending
workloads every 500 milliseconds; stable workloads retain the normal resync cadence.
The gateway applies watched updates immediately, without waiting for its health
poll timer. Normal watch renewal does not withdraw an unchanged acknowledgment.

The target is a networking handoff within five seconds **after** scheduling,
image availability, a READY CRI sandbox, and a healthy VPN gateway. This is not a
hard deadline or an established cluster latency guarantee: API outages, slow
responses, scheduling, image pulls and VPN startup can delay it. The init container
continues waiting rather than allowing unprotected traffic or restarting every
five seconds. Validate the target in your cluster using the elapsed startup logs.

Init logs show waiting, ready, and failure with elapsed time. Agent logs show
waiting-sandbox, waiting-gateway, waiting-config-ack, programming and ready stages.
Controller logs report pending acknowledgment counts; gateway logs report validated
configuration application and readiness transitions. No VPN profile, token or
client-IP list is logged.

Upgrade the controller, gateway, agent and init images together with the chart:
the API reader requires the new projected token, ServiceAccount and Role resources.
The workload init image is injected during Pod creation; existing Pods keep their
original injected image.
