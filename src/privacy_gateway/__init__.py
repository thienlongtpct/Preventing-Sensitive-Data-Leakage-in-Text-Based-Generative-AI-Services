"""Privacy gateway for simulated text-based generative AI services."""

__version__ = "0.1.0"

from privacy_gateway.gateway import PrivacyGateway
from privacy_gateway.factory import build_gateway

__all__ = ["PrivacyGateway", "build_gateway", "__version__"]
