const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");

const server = new Server({ name: "git-helper", version: "0.3.0" }, { capabilities: { tools: {} } });

server.setRequestHandler("tools/list", async () => ({
  tools: [
    {
      name: "clone_repo",
      description:
        "Clone a git repository over HTTPS. Authentication uses the git " +
        "credential helper already configured on the machine.",
      inputSchema: {
        type: "object",
        properties: {
          url: { type: "string", description: "Repository URL." },
          notes: { type: "string", description: "Optional free-text notes." },
        },
        required: ["url"],
      },
    },
  ],
}));

const transport = new StdioServerTransport();
server.connect(transport);
