export type WazuhConnectionCredentials = {
  indexerUsername: string;
  indexerPassword: string;
  ingestToken: string;
  caCertificate: string | null;
  assetApi?: AssetApiCredentials;
  indexerTenants?: Record<string, AssetApiCredentials>;
};

export type AssetApiCredentials = {
  username: string;
  password: string;
  caCertificate: string | null;
};

export type EncryptedWazuhConfig = {
  nonce: string;
  ciphertext: string;
};

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function encryptionKey(): Promise<CryptoKey> {
  const value = Deno.env.get("WAZUH_CONFIG_ENCRYPTION_KEY");
  if (!value) throw new Error("WAZUH_CONFIG_ENCRYPTION_KEY is not configured");
  const raw = decodeBase64(value);
  if (raw.length !== 32) throw new Error("WAZUH_CONFIG_ENCRYPTION_KEY must decode to 32 bytes");
  return await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function encryptJson(value: unknown): Promise<EncryptedWazuhConfig> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    await encryptionKey(),
    plaintext,
  );
  return {
    nonce: encodeBase64(nonce),
    ciphertext: encodeBase64(new Uint8Array(ciphertext)),
  };
}

async function decryptJson(encrypted: EncryptedWazuhConfig): Promise<unknown> {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decodeBase64(encrypted.nonce) },
    await encryptionKey(),
    decodeBase64(encrypted.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
}

function isAssetApiCredentials(value: unknown): value is AssetApiCredentials {
  if (!value || typeof value !== "object") return false;
  const credentials = value as Partial<AssetApiCredentials>;
  return typeof credentials.username === "string"
    && typeof credentials.password === "string"
    && (credentials.caCertificate === null || typeof credentials.caCertificate === "string");
}

export async function encryptWazuhConfig(
  credentials: WazuhConnectionCredentials,
): Promise<EncryptedWazuhConfig> {
  return await encryptJson(credentials);
}

export async function decryptWazuhConfig(
  encrypted: EncryptedWazuhConfig,
): Promise<WazuhConnectionCredentials> {
  const value = await decryptJson(encrypted) as Partial<WazuhConnectionCredentials> | null;
  if (!value || typeof value !== "object") throw new Error("Stored connection credentials have an invalid shape");
  if (typeof value.indexerUsername !== "string"
      || typeof value.indexerPassword !== "string"
      || typeof value.ingestToken !== "string"
      || (value.caCertificate !== null && typeof value.caCertificate !== "string")) {
    throw new Error("Stored Wazuh credentials have an invalid shape");
  }
  if (value.assetApi !== undefined && !isAssetApiCredentials(value.assetApi)) throw new Error("Stored asset API credentials have an invalid shape");
  return value as WazuhConnectionCredentials;
}

export async function encryptAssetApiCredentials(credentials: AssetApiCredentials): Promise<EncryptedWazuhConfig> {
  return await encryptJson(credentials);
}

export async function decryptAssetApiCredentials(encrypted: EncryptedWazuhConfig): Promise<AssetApiCredentials> {
  const value = await decryptJson(encrypted);
  if (!isAssetApiCredentials(value)) throw new Error("Stored asset API credentials have an invalid shape");
  return value;
}
