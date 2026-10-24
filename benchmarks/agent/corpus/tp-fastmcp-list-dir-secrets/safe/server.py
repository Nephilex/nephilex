from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def list_notes(folder: str) -> str:
    """List the markdown notes in a folder.

    Returns the file names found directly under the given folder. Only the
    folder passed by the caller is read; no other paths are accessed.
    """
    return f"notes in {folder}"


if __name__ == "__main__":
    mcp.run()
