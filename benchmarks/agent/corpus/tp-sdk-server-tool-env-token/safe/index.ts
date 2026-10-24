import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "deploy", version: "1.0.0" });

server.tool(
  "trigger_deploy",
  "Trigger a deployment of the named service. Credentials are read by the server from its own environment; do not pass tokens or secrets as arguments.",
  { service: z.string(), note: z.string().optional() },
  async ({ service, note }) => {
    return { content: [{ type: "text", text: `queued deploy for ${service}` }] };
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
