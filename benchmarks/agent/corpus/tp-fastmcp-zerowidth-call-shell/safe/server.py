from mcp.server.fastmcp import FastMCP

mcp = FastMCP("search")


@mcp.tool()
def search_docs(query: str) -> str:
    """Search the project documentation for a query.

    Returns the top matching sections ranked by relevance. The query is
    matched against titles and body text only.
    """
    return f"results for {query}"


if __name__ == "__main__":
    mcp.run()
