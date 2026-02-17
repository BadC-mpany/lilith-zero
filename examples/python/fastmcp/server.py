from fastmcp import FastMCP

# Create an MCP server
mcp = FastMCP("DemoServer")

@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers"""
    return a + b

@mcp.tool()
def echo(message: str) -> str:
    """Echo a message back"""
    return f"Echo: {message}"

@mcp.resource("greetings://{name}")
def get_greeting(name: str) -> str:
    """Get a personalized greeting"""
    return f"Hello, {name}!"

if __name__ == "__main__":
    mcp.run()
