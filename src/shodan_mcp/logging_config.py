"""
Logging configuration for Shodan MCP server.

This module provides centralized logging configuration for both
Python standard logging and MCP protocol logging.
"""

import logging
import os

# Environment variable to control logging level
LOG_LEVEL = os.getenv("SHODAN_MCP_LOG_LEVEL", "INFO").upper()

# MCP protocol logging level (sent to clients)
MCP_LOG_LEVEL = os.getenv("SHODAN_MCP_PROTOCOL_LOG_LEVEL", "INFO").upper()

# Valid log levels
VALID_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def setup_logging(name: str = "shodan-mcp") -> logging.Logger:
    """
    Set up logging configuration for the Shodan MCP server.

    Args:
        name: Logger name (default: "shodan-mcp")

    Returns:
        Configured logger instance
    """
    # Validate log level
    level = LOG_LEVEL if LOG_LEVEL in VALID_LEVELS else "INFO"

    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level))

    # Remove existing handlers to avoid duplicates
    logger.handlers = []

    # Create console handler with custom format
    handler = logging.StreamHandler()
    handler.setLevel(getattr(logging, level))

    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(handler)

    return logger


def should_log_mcp(level: str) -> bool:
    """
    Determine if a message should be logged via MCP protocol.

    Args:
        level: The log level to check (DEBUG, INFO, WARNING, ERROR)

    Returns:
        True if the message should be logged via MCP
    """
    mcp_level = MCP_LOG_LEVEL if MCP_LOG_LEVEL in VALID_LEVELS else "INFO"

    level_order = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}

    return level_order.get(level, 0) >= level_order.get(mcp_level, 20)


class MCPLoggerWrapper:
    """
    Wrapper class to handle conditional MCP logging based on log level.
    """

    def __init__(self, context):
        self.context = context

    async def debug(self, message: str):
        """Log debug message if enabled."""
        if self.context and should_log_mcp("DEBUG"):
            await self.context.debug(message)

    async def info(self, message: str):
        """Log info message if enabled."""
        if self.context and should_log_mcp("INFO"):
            await self.context.info(message)

    async def warning(self, message: str):
        """Log warning message if enabled."""
        if self.context and should_log_mcp("WARNING"):
            await self.context.warning(message)

    async def error(self, message: str):
        """Log error message if enabled."""
        if self.context and should_log_mcp("ERROR"):
            await self.context.error(message)
