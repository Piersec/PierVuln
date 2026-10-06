import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.117.2";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const expectedJobToken = Deno.env.get("ARCHIVE_JOB_TOKEN");
const supabase = createClient(supabaseUrl, serviceKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});
const bucket = "wazuh-vulnerability-archives";
const maxFindingsPerArchive = 100;

function response(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

function constantTimeEqual(left: string, right: string) {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  if (a.length !== b.length) return false;
  let different = 0;
  for (let i = 0; i < a.length; i += 1) different |= a[i] ^ b[i];
  return different === 0;
}

async function sha256(bytes: Uint8Array) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((part) => part.toString(16).padStart(2, "0")).join("");
}

async function gzip(bytes: Uint8Array) {
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function jsonBytes(value: unknown) {
  return new TextEncoder().encode(JSON.stringify(value));
}

async function expireArchives(connectionId: string | null) {
  let query = supabase.from("archive_manifests")
    .select("id,object_path,bucket_name")
    .eq("status", "database_purged")
    .lte("expires_at", new Date().toISOString())
    .order("expires_at")
    .limit(100);
  if (connectionId) query = query.eq("connection_id", connectionId);
  const { data: manifests, error } = await query;
  if (error) throw error;
  let expired = 0;
  for (const manifest of manifests ?? []) {
    const { error: removeError } = await supabase.storage.from(manifest.bucket_name).remove([manifest.object_path]);
    if (removeError) {
      // An already-removed object is retried through the same path; no DB rows
      // remain, and the manifest remains available until storage cleanup succeeds.
      console.error(`[archive-runner] storage removal failed manifest=${manifest.id}`);
      continue;
    }
    const { data, error: expireError } = await supabase.rpc("expire_wazuh_archive", { p_manifest_id: manifest.id });
    if (expireError) throw expireError;
    if (data === true) expired += 1;
  }
  return expired;
}

async function archiveResolvedFindings(connectionId: string | null) {
  const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
  let outstandingQuery = supabase.from("archive_manifests")
    .select("id,bucket_name,object_path,checksum_sha256,finding_ids,status")
    .in("status", ["pending", "verified"])
    .order("created_at")
    .limit(100);
  if (connectionId) outstandingQuery = outstandingQuery.eq("connection_id", connectionId);
  const { data: outstandingManifests, error: outstandingError } = await outstandingQuery;
  if (outstandingError) throw outstandingError;
  const reservedFindingIds = new Set((outstandingManifests ?? []).flatMap((manifest) => manifest.finding_ids as string[]));
  let archived = 0;

  for (const manifest of outstandingManifests ?? []) {
    try {
      const { data: object, error: downloadError } = await supabase.storage.from(manifest.bucket_name).download(manifest.object_path);
      if (downloadError || !object) throw downloadError ?? new Error("Archive read-back returned no file");
      const bytes = new Uint8Array(await object.arrayBuffer());
      if (await sha256(bytes) !== manifest.checksum_sha256) {
        throw new Error("Existing archive checksum does not match its manifest");
      }
      if (manifest.status === "pending") {
        const { data: verified, error: verifyError } = await supabase.rpc("verify_wazuh_archive", { p_manifest_id: manifest.id });
        if (verifyError || verified !== true) throw verifyError ?? new Error("Manifest verification was rejected");
      }
      const { data: finalized, error: finalizeError } = await supabase.rpc("finalize_wazuh_archive", { p_manifest_id: manifest.id });
      if (finalizeError) throw finalizeError;
      archived += Number((finalized as { findingsPurged?: number }).findingsPurged ?? 0);
    } catch (error) {
      console.error(`[archive-runner] manifest=${manifest.id} retained for retry: ${error instanceof Error ? error.message.slice(0, 250) : "unknown"}`);
    }
  }

  let findingQuery = supabase.from("wazuh_findings")
    .select("id,connection_id,tenant_id,resolved_at")
    .eq("source_state", "resolved")
    .not("tenant_id", "is", null)
    .lte("resolved_at", cutoff)
    .order("resolved_at")
    .limit(maxFindingsPerArchive * 10);
  if (connectionId) findingQuery = findingQuery.eq("connection_id", connectionId);
  const { data: findings, error } = await findingQuery;
  if (error) throw error;

  const groups = new Map<string, NonNullable<typeof findings>>();
  for (const finding of findings ?? []) {
    if (!finding.tenant_id || reservedFindingIds.has(finding.id)) continue;
    const key = `${finding.tenant_id}:${finding.connection_id}`;
    const group = groups.get(key) ?? [];
    if (group.length < maxFindingsPerArchive) group.push(finding);
    groups.set(key, group);
  }

  for (const group of groups.values()) {
    if (!group.length) continue;
    const ids = group.map((finding) => finding.id);
    const tenantId = group[0].tenant_id!;
    const connectionId = group[0].connection_id;
    const { data: source, error: sourceError } = await supabase.rpc("prepare_archive_source", {
      p_finding_ids: ids, p_tenant_id: tenantId,
    });
    if (sourceError) throw sourceError;
    if (!source || typeof source.sourceFingerprint !== "string") throw new Error("Archive source verification is missing");

    const archive = {
      format: "piergv-wazuh-vulnerability-archive-v1",
      createdAt: new Date().toISOString(),
      tenantId,
      connectionId,
      findings: source.findings,
      cases: source.cases,
      comments: source.comments,
      events: source.events,
    };
    const compressed = await gzip(await jsonBytes(archive));
    const checksum = await sha256(compressed);
    const manifestId = crypto.randomUUID();
    const day = new Date().toISOString().slice(0, 10);
    const objectPath = `${tenantId}/${connectionId}/${day}/${manifestId}.json.gz`;
    const { error: uploadError } = await supabase.storage.from(bucket).upload(objectPath, compressed, {
      contentType: "application/gzip",
      upsert: false,
    });
    if (uploadError) throw uploadError;

    try {
      const { data: downloaded, error: downloadError } = await supabase.storage.from(bucket).download(objectPath);
      if (downloadError || !downloaded) throw downloadError ?? new Error("Archive read-back returned no file");
      const readback = new Uint8Array(await downloaded.arrayBuffer());
      if (await sha256(readback) !== checksum) throw new Error("Archive checksum mismatch after upload");

      const resolvedTimes = (source.findings as Array<{ resolved_at: string }>).map((finding) => Date.parse(finding.resolved_at)).filter(Number.isFinite);
      const { error: manifestError } = await supabase.from("archive_manifests").insert({
        id: manifestId,
        tenant_id: tenantId,
        connection_id: connectionId,
        bucket_name: bucket,
        object_path: objectPath,
        checksum_sha256: checksum,
        source_fingerprint: source.sourceFingerprint,
        record_count: group.length,
        finding_ids: ids,
        period_start: new Date(Math.min(...resolvedTimes)).toISOString(),
        period_end: new Date(Math.max(...resolvedTimes)).toISOString(),
        status: "pending",
      });
      if (manifestError) throw manifestError;
      const { data: verified, error: verifyError } = await supabase.rpc("verify_wazuh_archive", { p_manifest_id: manifestId });
      if (verifyError || verified !== true) throw verifyError ?? new Error("Manifest verification was rejected");
      const { data: finalized, error: finalizeError } = await supabase.rpc("finalize_wazuh_archive", { p_manifest_id: manifestId });
      if (finalizeError) throw finalizeError;
      archived += Number((finalized as { findingsPurged?: number }).findingsPurged ?? 0);
    } catch (error) {
      // Keep any manifest/object for internal investigation if created; never
      // remove the database source until checksum validation and finalization.
      console.error(`[archive-runner] manifest=${manifestId} retained; finalization failed: ${error instanceof Error ? error.message.slice(0, 250) : "unknown"}`);
    }
  }
  return archived;
}

Deno.serve(async (request) => {
  if (request.method !== "POST") return response(405, { error: "Method not allowed" });
  const suppliedToken = request.headers.get("x-archive-token") ?? "";
  if (suppliedToken.length < 16 || suppliedToken.length > 512) return response(401, { error: "Unauthorized" });
  let connectionId: string | null = null;
  const requestedConnection = request.headers.get("x-connection-id");
  if (requestedConnection) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(requestedConnection)) return response(401, { error: "Unauthorized" });
    const [{ data: credential, error: credentialError }, { data: connection, error: connectionError }] = await Promise.all([
      supabase.from("wazuh_ingest_credentials").select("token_sha256").eq("connection_id", requestedConnection).maybeSingle(),
      supabase.from("wazuh_connections").select("id").eq("id", requestedConnection).eq("is_active", true).maybeSingle(),
    ]);
    if (credentialError || connectionError || !credential || !connection || !constantTimeEqual(credential.token_sha256, await sha256(new TextEncoder().encode(suppliedToken)))) return response(401, { error: "Unauthorized" });
    connectionId = connection.id;
  } else if (!expectedJobToken || !constantTimeEqual(suppliedToken, expectedJobToken)) {
    return response(401, { error: "Unauthorized" });
  }
  try {
    const expiredManifests = await expireArchives(connectionId);
    const purgedFindings = await archiveResolvedFindings(connectionId);
    return response(200, { expiredManifests, purgedFindings });
  } catch (error) {
    console.error(`[archive-runner] retention failed: ${error instanceof Error ? error.message.slice(0, 300) : "unknown"}`);
    return response(500, { error: "Retention task failed; unverified data was not deleted" });
  }
});
