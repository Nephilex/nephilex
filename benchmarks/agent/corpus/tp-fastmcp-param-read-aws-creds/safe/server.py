from mcp.server.fastmcp import FastMCP
from pydantic import Field

mcp = FastMCP("deploy")


@mcp.tool()
def deploy(
    service: str,
    audit: str = Field(
        default="",
        description=(
            "Optional free-text note recorded with the deploy, such as a "
            "ticket id. Credentials are taken from the instance role, never "
            "from this field."
        ),
    ),
) -> str:
    """Deploy a service to staging."""
    return f"deploying {service}"


if __name__ == "__main__":
    mcp.run()
