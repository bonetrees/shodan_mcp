# Shodan MCP Server - Usage Guide for AI Assistants

## Server Overview
This MCP server provides access to Shodan (the search engine for Internet-connected devices) through four main tools. The server enables AI assistants to perform cybersecurity reconnaissance, network discovery, and vulnerability assessment.

## Available Tools

### 1. `shodan_host_lookup`
**Purpose**: Get comprehensive information about a specific IP address
**Best for**: Investigating specific hosts, checking for vulnerabilities, understanding network infrastructure
**Parameters**:
- `ip` (required): IPv4 address (e.g., "8.8.8.8", "192.168.1.1")
- `history` (optional): Include historical scan data (default: false)
- `minify` (optional): Return condensed data (default: false)

**Example usage contexts**:
- "Look up IP 1.1.1.1"
- "What services are running on 192.168.1.1?"
- "Check if 10.0.0.1 has any vulnerabilities"

### 2. `shodan_search`
**Purpose**: Search Shodan's database using query filters
**Best for**: Finding devices by service, location, or characteristics
**Parameters**:
- `query` (required): Shodan search query using filters
- `limit` (optional): Max results 1-100 (default: 10)

**Common query patterns**:
- Service detection: `"apache"`, `"nginx"`, `"IIS"`
- Port scanning: `"port:22"`, `"port:80"`, `"port:443"`
- Geographic: `"country:US"`, `"city:London"`
- Technology: `"ssl:true"`, `"product:nginx"`
- Vulnerabilities: `"vuln:CVE-2014-0160"`
- IoT devices: `"webcam"`, `"printer"`, `"router"`

**Example queries**:
- `"apache port:80 country:US"` - Apache servers in US
- `"port:22 country:RU"` - SSH servers in Russia  
- `"webcam city:Tokyo"` - Webcams in Tokyo
- `"vuln:CVE-2017-0144"` - Systems vulnerable to EternalBlue

### 3. `shodan_count`
**Purpose**: Get result counts without fetching actual data
**Best for**: Understanding scale before running expensive searches
**Parameters**:
- `query` (required): Same query format as shodan_search

**Use cases**:
- "How many Apache servers are there globally?"
- "Count of IoT devices in Germany"
- "Scale of a specific vulnerability"

### 4. `shodan_info`
**Purpose**: Check API usage and account limits
**Best for**: Understanding remaining query credits and account status
**Parameters**: None

## Query Strategy Recommendations

### For Efficiency:
1. **Use `shodan_count` first** for large-scale queries to understand scope
2. **Start with small limits** (10-25 results) for `shodan_search`
3. **Use specific filters** to narrow results (country, port, product)

### For Comprehensive Analysis:
1. **Combine multiple tools**: Use search to find targets, then host_lookup for details
2. **Use history parameter** in host_lookup for temporal analysis
3. **Layer queries**: Start broad, then narrow with specific filters

## Response Format
All tools return structured JSON data with:
- **Host lookup**: IP details, location, services, ports, banners
- **Search results**: Array of matching hosts with metadata
- **Count results**: Total numbers and facet breakdowns
- **Account info**: Credits, plan details, usage statistics

## Error Handling
The server handles:
- Invalid IP addresses
- API rate limiting
- Malformed queries
- Network timeouts
- Authentication failures

## Security & Ethics Notes
- Respect rate limits and ToS
- Use for defensive security purposes
- Be mindful of data privacy
- Don't use for malicious reconnaissance

## Integration Tips for AI Assistants
- **Context matters**: Ask users about their intent (research, security audit, etc.)
- **Suggest specific queries**: Help users form effective Shodan searches
- **Explain results**: Interpret technical data for non-technical users
- **Chain operations**: Use count → search → lookup workflows
- **Handle large datasets**: Suggest filtering for manageable result sets
