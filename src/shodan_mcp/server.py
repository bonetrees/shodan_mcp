#!/usr/bin/env python3
"""
Shodan MCP Server

This server provides tools to interact with the Shodan API for IP address lookups,
host information, and vulnerability scanning through the Model Context Protocol.
"""

import asyncio
import json
import logging
from typing import Any, Sequence

import shodan
from decouple import config
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    LoggingLevel,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shodan-mcp")

# Initialize Shodan API
try:
    SHODAN_API_KEY = config("SHODAN_API_KEY")
    api = shodan.Shodan(SHODAN_API_KEY)
    logger.info("Shodan API initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Shodan API: {e}")
    api = None

# Create MCP server instance
server = Server("shodan-mcp")


@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """List available Shodan tools."""
    return [
        Tool(
            name="shodan_host_lookup",
            description="""Look up comprehensive information about a specific IPv4 address using Shodan.
            
This tool provides detailed host intelligence including:
• Open ports and running services with banners
• Geographic location and network ownership details  
• Service versions and product information
• Historical scan data (if requested)
• Vulnerability information when available

Best for: Investigating specific hosts, security assessment, network reconnaissance.
Common use cases: "What services run on 8.8.8.8?", "Check if this IP has vulnerabilities", "Get details about this server"

Tip: Use history=true for temporal analysis of how services have changed over time.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IPv4 address to look up (e.g., '8.8.8.8', '192.168.1.1'). Must be a valid IPv4 address.",
                    },
                    "history": {
                        "type": "boolean",
                        "description": "Include historical scan data showing how services have changed over time (default: False). Useful for tracking infrastructure changes.",
                        "default": False,
                    },
                    "minify": {
                        "type": "boolean",
                        "description": "Return minimal data with only essential fields (default: False). Use when you need basic info quickly.",
                        "default": False,
                    },
                },
                "required": ["ip"],
            },
        ),
        Tool(
            name="shodan_search",
            description="""Search Shodan's database using flexible query filters to find devices and services.

This tool enables discovery of Internet-connected devices using Shodan's powerful search syntax:
• Service detection: 'apache', 'nginx', 'ssh', 'ftp'
• Port scanning: 'port:22', 'port:80', 'port:443'
• Geographic filtering: 'country:US', 'city:London', 'geo:"37.7749,-122.4194"'
• Technology stack: 'ssl:true', 'product:nginx', 'version:1.18'
• Vulnerability hunting: 'vuln:CVE-2014-0160', 'vuln:ms17-010'
• IoT device discovery: 'webcam', 'printer', 'router', 'scada'
• Network ranges: 'net:192.168.1.0/24'

Example powerful queries:
• 'apache port:80 country:US' - US Apache servers
• 'port:22 "SSH-2.0-OpenSSH" country:RU' - Russian OpenSSH servers
• 'webcam city:Tokyo' - Tokyo webcams
• 'vuln:CVE-2017-0144' - EternalBlue vulnerable systems
• 'product:"Hikvision IP Camera"' - Specific camera models

Best for: Large-scale reconnaissance, vulnerability research, IoT discovery, threat hunting.
Tip: Start with broad queries, then narrow with additional filters. Use shodan_count first for large result sets.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Shodan search query using filters and keywords. Examples: 'apache port:80', 'country:US ssl:true', 'webcam city:London', 'vuln:CVE-2014-0160'. Combine multiple filters with spaces.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default: 10, max: 100). Start small for exploration, increase for comprehensive analysis. Use shodan_count first to estimate result sizes.",
                        "default": 10,
                        "minimum": 1,
                        "maximum": 100,
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="shodan_count",
            description="""Get the total count of search results for a Shodan query without fetching actual host data.

This tool is essential for:
• Understanding the scale of search results before running expensive queries
• Researching global trends and statistics
• Planning comprehensive data collection strategies
• Validating query effectiveness without using search credits

Returns total counts plus faceted breakdowns when available (by country, organization, port, etc.).

Best for: Scale assessment, trend analysis, query validation.
Example uses: "How many Apache servers exist globally?", "Count of IoT devices in Germany", "Scale of CVE-2017-0144 exposure"

Tip: Always use this before large shodan_search operations to understand result scope and plan accordingly.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Shodan search query to count results for. Uses same syntax as shodan_search. Examples: 'port:22', 'apache country:US', 'vuln:CVE-2017-0144'.",
                    }
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="shodan_info",
            description="""Get information about your Shodan API account including usage limits and current status.

Returns detailed account information:
• Query credits remaining (for search operations)
• Scan credits available (for network scanning)
• Number of monitored IPs in your account
• Current subscription plan details
• HTTPS API access status
• Unlocked features and remaining unlocks

Best for: Resource planning, quota management, understanding API limitations.
Use cases: "How many searches can I still do?", "What's my current plan?", "Do I have scan credits available?"

Tip: Check this regularly during intensive research sessions to avoid hitting rate limits.""",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls for Shodan operations."""

    if not api:
        return [
            TextContent(
                type="text",
                text="Error: Shodan API not initialized. Please check your SHODAN_API_KEY environment variable.",
            )
        ]

    try:
        if name == "shodan_host_lookup":
            ip = arguments.get("ip")
            history = arguments.get("history", False)
            minify = arguments.get("minify", False)

            if not ip:
                return [TextContent(type="text", text="Error: IP address is required")]

            logger.info(f"Looking up IP: {ip}")
            host_info = api.host(ip, history=history, minify=minify)

            # Format the response nicely
            response = {
                "ip": host_info.get("ip_str"),
                "country": host_info.get("country_name"),
                "city": host_info.get("city"),
                "organization": host_info.get("org"),
                "isp": host_info.get("isp"),
                "asn": host_info.get("asn"),
                "ports": host_info.get("ports", []),
                "hostnames": host_info.get("hostnames", []),
                "last_update": host_info.get("last_update"),
                "services": [],
            }

            # Extract service information
            for service in host_info.get("data", []):
                service_info = {
                    "port": service.get("port"),
                    "protocol": service.get("transport"),
                    "service": service.get("product"),
                    "version": service.get("version"),
                    "banner": (
                        service.get("data", "")[:200] + "..."
                        if len(service.get("data", "")) > 200
                        else service.get("data", "")
                    ),
                }
                response["services"].append(service_info)

            return [
                TextContent(
                    type="text",
                    text=f"**Shodan Host Information for {ip}**\n\n"
                    + json.dumps(response, indent=2, default=str),
                )
            ]

        elif name == "shodan_search":
            query = arguments.get("query")
            limit = min(arguments.get("limit", 10), 100)  # Cap at 100

            if not query:
                return [
                    TextContent(type="text", text="Error: Search query is required")
                ]

            logger.info(f"Searching Shodan with query: {query}")
            results = api.search(query, limit=limit)

            response = {
                "query": query,
                "total_results": results.get("total", 0),
                "results_returned": len(results.get("matches", [])),
                "matches": [],
            }

            for match in results.get("matches", []):
                match_info = {
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "protocol": match.get("transport"),
                    "country": match.get("location", {}).get("country_name"),
                    "city": match.get("location", {}).get("city"),
                    "organization": match.get("org"),
                    "service": match.get("product"),
                    "version": match.get("version"),
                    "timestamp": match.get("timestamp"),
                }
                response["matches"].append(match_info)

            return [
                TextContent(
                    type="text",
                    text=f"**Shodan Search Results for '{query}'**\n\n"
                    + json.dumps(response, indent=2, default=str),
                )
            ]

        elif name == "shodan_count":
            query = arguments.get("query")

            if not query:
                return [
                    TextContent(type="text", text="Error: Search query is required")
                ]

            logger.info(f"Counting results for query: {query}")
            count_info = api.count(query)

            response = {
                "query": query,
                "total_results": count_info.get("total", 0),
                "facets": count_info.get("facets", {}),
            }

            return [
                TextContent(
                    type="text",
                    text=f"**Shodan Count Results for '{query}'**\n\n"
                    + json.dumps(response, indent=2, default=str),
                )
            ]

        elif name == "shodan_info":
            logger.info("Getting Shodan API info")
            info = api.info()

            response = {
                "query_credits": info.get("query_credits"),
                "scan_credits": info.get("scan_credits"),
                "monitored_ips": info.get("monitored_ips"),
                "plan": info.get("plan"),
                "https": info.get("https"),
                "unlocked": info.get("unlocked"),
                "unlocked_left": info.get("unlocked_left"),
            }

            return [
                TextContent(
                    type="text",
                    text="**Shodan API Account Information**\n\n"
                    + json.dumps(response, indent=2, default=str),
                )
            ]

        else:
            return [TextContent(type="text", text=f"Error: Unknown tool '{name}'")]

    except shodan.APIError as e:
        logger.error(f"Shodan API error: {e}")
        return [TextContent(type="text", text=f"Shodan API Error: {str(e)}")]
    except Exception as e:
        logger.error(f"Unexpected error in {name}: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]


async def main():
    """Main entry point for the Shodan MCP server."""
    # Run the server using stdio transport
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="shodan-mcp",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
