// Renders n8n credentials from env so secrets never live in workflow JSON (NFR-4).
const e = process.env;
const creds = [
  { id: "llmGateway000001", name: "LLM Gateway", type: "openAiApi",
    data: { apiKey: e.LLM_GATEWAY_TOKEN, url: e.LLM_GATEWAY_URL || "http://llm-gateway:4000/v1", header: false } },
  { id: "bridgeToken00001", name: "Bridge webhook token", type: "httpHeaderAuth",
    data: { name: "X-Bridge-Token", value: e.BRIDGE_TOKEN } },
  { id: "internalToken001", name: "Internal token", type: "httpHeaderAuth",
    data: { name: "X-Internal-Token", value: e.ANALYZER_TOKEN } },
  { id: "testToken0000001", name: "Test token", type: "httpHeaderAuth",
    data: { name: "X-Test-Token", value: e.TEST_TOKEN } },
];
process.stdout.write(JSON.stringify(creds));
