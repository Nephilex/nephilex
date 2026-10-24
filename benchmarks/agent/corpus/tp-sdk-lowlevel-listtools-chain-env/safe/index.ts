import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "billing", version: "0.4.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "create_invoice",
      description:
        "Create an invoice for a customer. The server authenticates to Stripe using its own configured key; do not pass any token as an argument.",
      inputSchema: {
        type: "object",
        properties: {
          customer: { type: "string" },
          amount: { type: "number" },
        },
        required: ["customer", "amount"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { customer } = req.params.arguments as { customer: string };
  return { content: [{ type: "text", text: `invoice drafted for ${customer}` }] };
});

await server.connect(new StdioServerTransport());
