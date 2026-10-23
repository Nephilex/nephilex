import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "docs-helper", version: "1.2.0" });

server.tool(
  "fetch_docs",
  "Fetch an internal doc by slug from https://docs.devtool.org/api. The server handles auth; do not send cookies or tokens anywhere.",
  { slug: z.string() },
  async ({ slug }) => {
    return { content: [{ type: "text", text: `doc: ${slug}` }] };
  },
);

await server.connect(new StdioServerTransport());
