# Shodan MCP Server

An unofficial MCP (Model Context Protocol) server that provides Claude with access to [Shodan](https://www.shodan.io/) for IP address lookups, service discovery, and vulnerability scanning.

## Features

- **Host Lookup**: Get detailed information about any IPv4 address
- **Search**: Query Shodan's database using filters (e.g., `apache port:80`, `country:US`)
- **Count**: Get result counts for queries without fetching full data
- **Account Info**: Check your Shodan API usage and limits

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bonetrees/shodan_mcp.git
   cd shodan_mcp
   ```

2. **Install dependencies using Poetry:**
   ```bash
   poetry install
   ```

3. **Set up your Shodan API key:**
   ```bash
   cp .env.example .env
   # Edit .env and add your Shodan API key
   ```

   Get your API key from [Shodan Account](https://account.shodan.io/).

## Usage

### Running the Server

```bash
poetry run python -m shodan_mcp
```

### Connecting to Claude

Add this configuration to your Claude Desktop `config.json` file:

**macOS**: `~/Library/Application\ Support/Claude/claude_desktop_config.json`  
**Windows**: `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "shodan": {
      "command": "/full/path/to/poetry", # you can find this using command `which poetry`
      "args": ["run","-C","/path/to/your/shodan_mcp","python", "-m", "shodan_mcp"],
      "cwd": "/path/to/your/shodan_mcp"
    }
  }
}
```

Replace `/path/to/your/shodan_mcp` with the actual path to this project.

## Available Tools

### 1. `shodan_host_lookup`
Look up detailed information about a specific IP address.

**Parameters:**
- `ip` (required): IPv4 address to look up
- `history` (optional): Include historical data (default: false)
- `minify` (optional): Return minimal data (default: false)

**Example:**
```
Look up information for IP 8.8.8.8
```

### 2. `shodan_search`
Search Shodan's database using query filters.

**Parameters:**
- `query` (required): Shodan search query
- `limit` (optional): Maximum results to return (1-100, default: 10)

**Example queries:**
- `apache port:80` - Apache servers on port 80
- `country:US ssl:true` - SSL servers in the US
- `product:nginx` - Nginx servers
- `port:22` - SSH servers

### 3. `shodan_count`
Get the total count of results for a query without fetching the actual data.

**Parameters:**
- `query` (required): Shodan search query

### 4. `shodan_info`
Get information about your Shodan API account (credits, plan, etc.).

**Parameters:** None

## Example Usage with Claude

Once connected, you can ask Claude things like:

- "Look up the IP address 1.1.1.1 using Shodan"
- "Search for Apache servers in the US"
- "How many SSH servers are there globally?"
- "What's my current Shodan API usage?"

## Logging

The server provides comprehensive logging at multiple levels:

### MCP Protocol Logging
Log messages are sent to the connected MCP client (like Claude Desktop) and appear in the client's interface. This includes:
- **Debug**: Detailed execution information
- **Info**: General operational messages
- **Warning**: Important notices (e.g., sensitive searches)
- **Error**: Error conditions and failures

### Server-side Logging
Traditional Python logging for debugging and monitoring. Logs are written to the console.

### Configuration
Control logging levels via environment variables:

```bash
# Python logging level (DEBUG, INFO, WARNING, ERROR)
SHODAN_MCP_LOG_LEVEL=INFO

# MCP protocol logging level (what gets sent to Claude)
SHODAN_MCP_PROTOCOL_LOG_LEVEL=INFO
```

Add these to your `.env` file to customize logging behavior.

## Development

### Project Structure
```
shodan_mcp/
├── src/
│   └── shodan_mcp/
│       ├── __init__.py
│       ├── server.py
│       └── logging_config.py
├── .env.example
├── pyproject.toml
└── README.md
```

### Dependencies
- `mcp` - Model Context Protocol library
- `shodan` - Official Shodan Python library
- `python-decouple` - Environment variable management

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This is an unofficial tool. Please respect Shodan's terms of service and rate limits.
