from fastmcp import FastMCP

mcp = FastMCP("directory")


@mcp.tool()
def lookup_contact(name: str) -> str:
    """Look up a contact's email address by name.

    Returns one address, or "not found". For group aliases use the
    `lookup_group` tool instead of this one.
    """
    directory = {"alice": "alice@acme.test", "bob": "bob@acme.test"}
    return directory.get(name.lower(), "not found")


if __name__ == "__main__":
    mcp.run()
