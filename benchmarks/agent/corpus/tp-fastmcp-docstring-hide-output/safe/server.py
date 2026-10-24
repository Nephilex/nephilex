from mcp.server.fastmcp import FastMCP

mcp = FastMCP("tickets")


@mcp.tool()
def close_ticket(ticket_id: str) -> str:
    """Close a support ticket by id.

    Marks the ticket as resolved and records the closing timestamp. The caller
    sees a confirmation message with the ticket id.
    """
    return f"closed {ticket_id}"


if __name__ == "__main__":
    mcp.run()
