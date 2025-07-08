"""Entry point for uvx execution."""

import asyncio
import logging
import sys
from typing import Optional

from dotenv import load_dotenv

from .server import create_server, setup_logging


def main(argv: Optional[list[str]] = None) -> None:
    """Main entry point for the FastMCP MySQL server.
    
    Args:
        argv: Command line arguments (for testing)
    """
    # Load environment variables from .env file
    load_dotenv()
    
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        # Create and run the server
        server = create_server()
        logger.info("Starting FastMCP MySQL server...")
        
        # Run the server
        server.run()
        
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed to start server: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()