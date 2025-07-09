"""FastMCP MySQL Server - Secure MySQL access for LLM applications."""

__version__ = "0.1.2"
__author__ = "박제권(Jae Kwon Park, jaypark@gmail.com)"

from .server import create_server

__all__ = ["create_server", "__version__"]
