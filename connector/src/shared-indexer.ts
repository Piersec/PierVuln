import { WazuhIndexerClient, type ScrollPage, type WazuhHit } from "./wazuh.js";

export type SnapshotIndexer = Pick<WazuhIndexerClient, "getVersion" | "countDocuments" | "startScroll" | "continueScroll" | "clearScroll">;

// Publish one complete snapshot only after every tenant has been downloaded successfully.
export class SharedIndexer implements SnapshotIndexer {
  private cursors: { client: WazuhIndexerClient; page: ScrollPage }[] = [];
  private buffer: WazuhHit[] = [];
  private size = 500;
  private total = 0;
  private current = 0;
  constructor(private readonly clients: WazuhIndexerClient[]) {
    if (!clients.length) throw new Error("Nenhum acesso de empresa configurado.");
  }
  async getVersion(signal?: AbortSignal) { return this.clients[0].getVersion(signal); }
  async countDocuments(signal?: AbortSignal) {
    let total = 0;
    for (const client of this.clients) total += await client.countDocuments(signal);
    return total;
  }
  async startScroll(size: number, _keepAlive: string, signal?: AbortSignal): Promise<ScrollPage> {
    this.size = size; this.total = 0; this.current = 0; this.buffer = [];
    try {
      for (const client of this.clients) {
        const page = await client.startScroll(size, "30m", signal);
        this.cursors.push({ client, page });
        if (page.total === null) throw new Error("A contagem da empresa não é exata.");
        this.total += page.total;
      }
      return await this.next(signal);
    } catch (error) { await this.clearScroll("shared"); throw error; }
  }
  async continueScroll(_id: string, _keepAlive: string, signal?: AbortSignal) { return this.next(signal); }
  private async next(signal?: AbortSignal): Promise<ScrollPage> {
    while (this.buffer.length < this.size && this.current < this.cursors.length) {
      const cursor = this.cursors[this.current];
      this.buffer.push(...cursor.page.hits);
      if (cursor.page.hits.length < this.size) this.current += 1;
      else cursor.page = await cursor.client.continueScroll(cursor.page.scrollId, "30m", signal);
    }
    return { hits: this.buffer.splice(0, this.size), total: this.total, scrollId: "shared" };
  }
  async clearScroll(_id: string) {
    await Promise.allSettled(this.cursors.map(({ client, page }) => client.clearScroll(page.scrollId)));
    this.cursors = []; this.buffer = [];
  }
}
