"""FastMCP MySQL Server - Secure MySQL access for LLM applications."""

__version__ = "0.1.0"
__author__ = "FastMCP MySQL Contributors"

from .server import create_server

__all__ = ["create_server", "__version__"]