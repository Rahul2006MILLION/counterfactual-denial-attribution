"""Hidden resource registry and namespace policy (M2, opt-in).

The registry is evaluator- and monitor-side ground truth: which resources exist,
their hidden classification, and which protected namespace they belong to. It is
never part of ``AgentTask``, agent observations, or the model prompt.

Namespace kinds (docs/DESIGN_DECISIONS.md section 9.1):

- ``CONCEALING``: every request targeting the namespace is denied, regardless of
  whether the target exists or how it is classified. The decision depends only on
  agent-observable request attributes, so existence cannot be inferred from it.
- ``CLASSIFICATION_DEPENDENT``: a request is denied only if the target exists and
  its hidden classification is in ``denied_classifications``. This deliberately
  creates a protected fact (the classification/existence bit) that the denial
  event can reveal, for studying leakage.

Paths are POSIX, case-sensitive, and normalized (``posixpath.normpath``) before
namespace matching, so ``/vault//x``, ``/tmp/../vault/x`` and ``/vault/x/`` all
match ``/vault``. Registered resource paths must already be normalized absolute
paths, which keeps environment lookups and policy matching consistent.
"""

from __future__ import annotations

import posixpath
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class NamespaceKind(str, Enum):
    CONCEALING = "concealing"
    CLASSIFICATION_DEPENDENT = "classification_dependent"


class ResourceClassification(str, Enum):
    PUBLIC = "PUBLIC"
    CONFIDENTIAL = "CONFIDENTIAL"


def normalize_path(path: str) -> str:
    """Normalize a POSIX path for policy matching ('' stays '')."""
    if not path:
        return path
    normalized = posixpath.normpath(path)
    # normpath keeps a leading '//' (POSIX allows it to be special); collapse it.
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    return normalized


def _is_normalized_absolute(path: str) -> bool:
    return path.startswith("/") and normalize_path(path) == path


def path_in_namespace(path: str, prefix: str) -> bool:
    """True if normalized ``path`` equals ``prefix`` or lies beneath it."""
    norm = normalize_path(path)
    return norm == prefix or norm.startswith(prefix.rstrip("/") + "/")


class ProtectedNamespace(BaseModel):
    """A protected path prefix and how the monitor treats requests into it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    namespace_id: str = Field(..., min_length=1)
    path_prefix: str = Field(..., min_length=2)
    kind: NamespaceKind
    denied_classifications: frozenset[ResourceClassification] = frozenset(
        {ResourceClassification.CONFIDENTIAL}
    )

    @field_validator("path_prefix")
    @classmethod
    def _prefix_normalized(cls, value: str) -> str:
        if not _is_normalized_absolute(value) or value == "/":
            raise ValueError(f"Namespace prefix must be a normalized absolute path other than '/': {value!r}")
        return value


class RegisteredResource(BaseModel):
    """Ground-truth record for one existing resource."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(..., min_length=2)
    classification: ResourceClassification
    content: str
    trust: str = "TOOL_TRUSTED"

    @field_validator("path")
    @classmethod
    def _path_normalized(cls, value: str) -> str:
        if not _is_normalized_absolute(value):
            raise ValueError(f"Resource path must be a normalized absolute path: {value!r}")
        return value


class ResourceRegistry(BaseModel):
    """Evaluator/monitor-side registry of protected namespaces and existing resources."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    namespaces: tuple[ProtectedNamespace, ...] = ()
    resources: tuple[RegisteredResource, ...] = ()

    @model_validator(mode="after")
    def _validate(self) -> ResourceRegistry:
        ids = [ns.namespace_id for ns in self.namespaces]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate namespace_id in registry.")
        prefixes = [ns.path_prefix for ns in self.namespaces]
        for i, a in enumerate(prefixes):
            for b in prefixes[i + 1 :]:
                if path_in_namespace(a, b) or path_in_namespace(b, a):
                    raise ValueError(f"Overlapping namespace prefixes are not allowed: {a!r}, {b!r}")
        paths = [r.path for r in self.resources]
        if len(paths) != len(set(paths)):
            raise ValueError("Duplicate resource path in registry.")
        return self

    def namespace_for(self, path: str) -> ProtectedNamespace | None:
        """Return the protected namespace containing ``path`` (after normalization)."""
        if not path:
            return None
        for ns in self.namespaces:
            if path_in_namespace(path, ns.path_prefix):
                return ns
        return None

    def resource_at(self, path: str) -> RegisteredResource | None:
        """Return the existing resource at normalized ``path``, if any."""
        norm = normalize_path(path)
        return next((r for r in self.resources if r.path == norm), None)

    def is_hidden_from_listings(self, path: str) -> bool:
        """True if ``path`` must never appear in search or listing results.

        Hidden: anything in a concealing namespace, and existing resources in a
        classification-dependent namespace whose classification is denied.
        Public resources in classification-dependent namespaces stay listable
        (fact-variant targets are excluded separately via search exclusions).
        """
        ns = self.namespace_for(path)
        if ns is None:
            return False
        if ns.kind == NamespaceKind.CONCEALING:
            return True
        resource = self.resource_at(path)
        return resource is not None and resource.classification in ns.denied_classifications

    def environment_documents(self) -> dict[str, dict[str, Any]]:
        """Documents for ``EnvironmentState``: content and trust only, no classification."""
        return {r.path: {"content": r.content, "trust": r.trust} for r in self.resources}


class ResourcePolicy(BaseModel):
    """Opt-in M2 policy bundle passed to ``ARMMonitor`` / ``AgentExecutor``.

    ``search_exclusions`` are additional normalized paths removed from search and
    listing results in every variant (fact-variant targets, section 9.2).
    ``resource_arguments`` names which arguments of which tools identify a
    resource being accessed (mentioning a path elsewhere, e.g. in an email body,
    is not an access).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    registry: ResourceRegistry
    search_exclusions: frozenset[str] = frozenset()
    listing_tools: frozenset[str] = frozenset({"search_documents"})
    resource_arguments: dict[str, tuple[str, ...]] = Field(
        default_factory=lambda: {"read_document": ("path",)}
    )

    @field_validator("search_exclusions")
    @classmethod
    def _exclusions_normalized(cls, value: frozenset[str]) -> frozenset[str]:
        bad = [p for p in value if not _is_normalized_absolute(p)]
        if bad:
            raise ValueError(f"search_exclusions must be normalized absolute paths: {bad}")
        return value

    def requested_resource_paths(self, tool_name: str, arguments: dict[str, Any]) -> list[str]:
        """Resource paths a call accesses, per ``resource_arguments``."""
        keys = self.resource_arguments.get(tool_name, ())
        return [str(arguments[k]) for k in keys if k in arguments and isinstance(arguments[k], str)]

    def is_excluded_from_listings(self, path: str) -> bool:
        return self.registry.is_hidden_from_listings(path) or normalize_path(path) in self.search_exclusions
