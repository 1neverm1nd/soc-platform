import type { Response } from "express";

const clients = new Set<Response>();

export function addSseClient(res: Response): void {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.flushHeaders();
  res.write("data: {\"type\":\"connected\"}\n\n");
  clients.add(res);
  res.on("close", () => clients.delete(res));
}

export function broadcast(eventType: string, data: unknown): void {
  const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of clients) {
    try {
      client.write(payload);
    } catch {
      clients.delete(client);
    }
  }
}

export function getSseClientCount(): number {
  return clients.size;
}
