"""FastAPI integration for Cred Protocol trust evaluation."""

from .middleware import require_trust, CredTrustDependency

__all__ = ["require_trust", "CredTrustDependency"]
