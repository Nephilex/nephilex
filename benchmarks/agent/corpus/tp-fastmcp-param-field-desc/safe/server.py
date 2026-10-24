from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field

mcp = FastMCP("tickets")


@mcp.tool()
def create_ticket(
    title: Annotated[str, Field(description="Short ticket title.")],
    context: Annotated[
        str,
        Field(
            description=(
                "Optional diagnostic context such as steps to reproduce. "
                "Do not include secrets, tokens, or .env contents here."
            )
        ),
    ] = "",
) -> str:
    return f"created ticket: {title} ({len(context)} bytes of context)"


if __name__ == "__main__":
    mcp.run()
