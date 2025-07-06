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
    LoggingLevel
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
            description="Look up information about a specific IP address using Shodan",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IPv4 address to look up (e.g., '8.8.8.8')"
                    },
                    "history": {
                        "type": "boolean",
                        "description": "Include historical data (default: False)",
                        "default": False
                    },
                    "minify": {
                        "type": "boolean", 
                        "description": "Return minimal data (default: False)",
                        "default": False
                    }
                },
                "required": ["ip"]
            }
        ),
        Tool(
            name="shodan_search",
            description="Search Shodan using query filters (e.g., 'apache port:80', 'country:US')",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Shodan search query (e.g., 'apache', 'port:22', 'country:US ssl:true')"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default: 10, max: 100)",
                        "default": 10,
                        "minimum": 1,
                        "maximum": 100
                    }
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="shodan_count",
            description="Get the count of search results for a Shodan query without returning the actual results",
            inputSchema={
                "type": "object", 
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Shodan search query to count results for"
                    }
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="shodan_info",
            description="Get information about your Shodan API account (query credits, scan credits, etc.)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls for Shodan operations."""
    
    if not api:
        return [TextContent(
            type="text",
            text="Error: Shodan API not initialized. Please check your SHODAN_API_KEY environment variable."
        )]
    
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
                "services": []
            }
            
            # Extract service information
            for service in host_info.get("data", []):
                service_info = {
                    "port": service.get("port"),
                    "protocol": service.get("transport"),
                    "service": service.get("product"),
                    "version": service.get("version"),
                    "banner": service.get("data", "")[:200] + "..." if len(service.get("data", "")) > 200 else service.get("data", "")
                }
                response["services"].append(service_info)
            
            return [TextContent(
                type="text",
                text=f"**Shodan Host Information for {ip}**\n\n" + 
                     json.dumps(response, indent=2, default=str)
            )]
            
        elif name == "shodan_search":
            query = arguments.get("query")
            limit = min(arguments.get("limit", 10), 100)  # Cap at 100
            
            if not query:
                return [TextContent(type="text", text="Error: Search query is required")]
            
            logger.info(f"Searching Shodan with query: {query}")
            results = api.search(query, limit=limit)
            
            response = {
                "query": query,
                "total_results": results.get("total", 0),
                "results_returned": len(results.get("matches", [])),
                "matches": []
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
                    "timestamp": match.get("timestamp")
                }
                response["matches"].append(match_info)
            
            return [TextContent(
                type="text",
                text=f"**Shodan Search Results for '{query}'**\n\n" + 
                     json.dumps(response, indent=2, default=str)
            )]
            
        elif name == "shodan_count":
            query = arguments.get("query")
            
            if not query:
                return [TextContent(type="text", text="Error: Search query is required")]
            
            logger.info(f"Counting results for query: {query}")
            count_info = api.count(query)
            
            response = {
                "query": query,
                "total_results": count_info.get("total", 0),
                "facets": count_info.get("facets", {})
            }
            
            return [TextContent(
                type="text",
                text=f"**Shodan Count Results for '{query}'**\n\n" + 
                     json.dumps(response, indent=2, default=str)
            )]
            
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
                "unlocked_left": info.get("unlocked_left")
            }
            
            return [TextContent(
                type="text",
                text="**Shodan API Account Information**\n\n" + 
                     json.dumps(response, indent=2, default=str)
            )]
        
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
                    experimental_capabilities={}
                )
            )
        )

if __name__ == "__main__":
    asyncio.run(main())
