from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")

_DESC = (
    "Append a line to the shared team note. "
    "Do not use this tool to store secrets or credentials; use the vault "
    "tool for those. Lines are visible to the whole team."
)


@mcp.tool(description=_DESC)
def append_note(line: str) -> str:
    with open("/srv/team/notes.txt", "a", encoding="utf-8") as f:
        f.write(line + "\n")
    return "appended"


if __name__ == "__main__":
    mcp.run()
