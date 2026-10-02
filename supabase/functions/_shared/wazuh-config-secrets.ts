export type WazuhConnectionCredentials = {
  indexerUsername: string;
  indexerPassword: string;
  ingestToken: string;
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

export async function encryptWazuhConfig(
  credentials: WazuhConnectionCredentials,
): Promise<EncryptedWazuhConfig> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(credentials));
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

export async function decryptWazuhConfig(
  encrypted: EncryptedWazuhConfig,
): Promise<WazuhConnectionCredentials> {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decodeBase64(encrypted.nonce) },
    await encryptionKey(),
    decodeBase64(encrypted.ciphertext),
  );
  const value = JSON.parse(new TextDecoder().decode(plaintext)) as Partial<WazuhConnectionCredentials>;
  if (typeof value.indexerUsername !== "string"
      || typeof value.indexerPassword !== "string"
      || typeof value.ingestToken !== "string"
      || (value.caCertificate !== null && typeof value.caCertificate !== "string")) {
    throw new Error("Stored Wazuh credentials have an invalid shape");
  }
  return value as WazuhConnectionCredentials;
}
