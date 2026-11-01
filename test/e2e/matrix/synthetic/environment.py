"""Immutable read-only identities for one explicitly approved k3d CNI context.

This is not a traffic/fixture capability. Only the existing flannel entrypoint
is wired to mutating Lifecycle, adapter, CRI, cleanup and advanced fixtures.
"""
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Environment:
    variant: str = "flannel"

    def __post_init__(self):
        if type(self.variant) is not str or self.variant not in ("flannel", "calico"):
            raise ValueError("Unsupported synthetic environment identity.")

    @property
    def context(self):
        return "k3d-ratatoskr-" + self.variant

    @property
    def nodes(self):
        prefix = self.context
        return (prefix + "-server-0", prefix + "-agent-0", prefix + "-agent-1")


FLANNEL = Environment()
CALICO = Environment("calico")
