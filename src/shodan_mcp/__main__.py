"""
Main entry point for the Shodan MCP server.
Allows running the server with: python -m shodan_mcp
"""

from .server import main

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
