// UI-layer shard preview helpers.
// Parse only the header portion of a .qcont shard file without touching decrypt logic.

import { LEGACY_QCONT_FORMAT_VERSION, QCONT_FORMAT_VERSION } from '../core/crypto/constants.js';
import { parseManifestBundleBytes } from '../core/crypto/manifest/manifest-bundle.js';

export async function parseQcontShardPreviewFile(file) {
  const decoder = new TextDecoder();
  const MAX_MANIFEST_LEN = 1024 * 1024;
  const MAX_BUNDLE_LEN = 4 * 1024 * 1024;
  const DIGEST_LEN = 64;
  let bytes = new Uint8Array(await file.slice(0, Math.min(file.size, 16384)).arrayBuffer());
  let dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const ensureBytes = async (requiredLength) => {
    if (bytes.length >= requiredLength) return;
    const toRead = Math.min(file.size, requiredLength);
    bytes = new Uint8Array(await file.slice(0, toRead).arrayBuffer());
    dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (bytes.length < requiredLength) {
      throw new Error('Shard header is truncated');
    }
  };

  await ensureBytes(6);
  const magic = decoder.decode(bytes.subarray(0, 4));
  if (magic !== 'QVC1') throw new Error('Invalid shard file');

  let offset = 4;
  const metaLen = dv.getUint16(offset, false);
  if (metaLen <= 0) throw new Error('Invalid shard metadata length');
  offset += 2;
  await ensureBytes(offset + metaLen);
  const metaJSON = JSON.parse(decoder.decode(bytes.subarray(offset, offset + metaLen)));
  if (metaJSON?.alg?.fmt === LEGACY_QCONT_FORMAT_VERSION) {
    throw new Error('Legacy shard format is not supported');
  }
  if (metaJSON?.alg?.fmt !== QCONT_FORMAT_VERSION) {
    throw new Error(`Unsupported shard format: expected ${QCONT_FORMAT_VERSION}`);
  }
  if (metaJSON?.hasKeyCommitment !== true) {
    throw new Error('Shard metadata must indicate hasKeyCommitment=true');
  }
  offset += metaLen;

  await ensureBytes(offset + 4);
  const manifestLen = dv.getUint32(offset, false);
  if (manifestLen <= 0 || manifestLen > MAX_MANIFEST_LEN) {
    throw new Error('Invalid embedded manifest length');
  }
  offset += 4 + manifestLen + DIGEST_LEN;

  await ensureBytes(offset + 4);
  const bundleLen = dv.getUint32(offset, false);
  if (bundleLen <= 0 || bundleLen > MAX_BUNDLE_LEN) {
    throw new Error('Invalid embedded bundle length');
  }
  offset += 4;
  await ensureBytes(offset + bundleLen + DIGEST_LEN + 4);
  const bundleBytes = bytes.subarray(offset, offset + bundleLen);
  const parsedBundle = parseManifestBundleBytes(bundleBytes, { requireCanonical: false });
  offset += bundleLen + DIGEST_LEN;

  await ensureBytes(offset + 4);
  const encapLen = dv.getUint32(offset, false);
  if (encapLen <= 0) throw new Error('Invalid encapsulated key length');
  offset += 4 + encapLen + 12 + 16;

  await ensureBytes(offset + 2);
  const qencMetaLen = dv.getUint16(offset, false);
  offset += 2 + qencMetaLen;

  await ensureBytes(offset + 1);
  const keyCommitLen = bytes[offset];
  offset += 1;
  if (keyCommitLen !== 32) {
    throw new Error(`Invalid key commitment length ${keyCommitLen}; expected 32`);
  }
  offset += keyCommitLen;
  await ensureBytes(offset + 2);
  const shardIndex = dv.getUint16(offset, false);

  if (!Number.isInteger(metaJSON?.t) || !Number.isInteger(metaJSON?.n)) {
    throw new Error('Shard metadata is missing n/t');
  }

  return {
    containerId: metaJSON.containerId,
    n: metaJSON.n,
    t: metaJSON.t,
    shardIndex,
    authPolicyLevel: parsedBundle.bundle.authPolicy.level,
    hasEmbeddedBundle: true,
  };
}

function classifyNonShardFile(file) {
  const name = String(file?.name || '').toLowerCase();
  if (name.endsWith('.qsig')) return 'signature';
  if (name.endsWith('.pqpk')) return 'pubkey';
  if (name.endsWith('.qvmanifest.json')) return 'manifest';
  if (name.endsWith('.sig')) return 'signature';
  if (name.endsWith('.ots')) return 'timestamp';
  return 'other';
}

export async function assessShardSelection(files) {
  if (!files.length) {
    return { state: 'empty', ready: false };
  }

  const parsed = [];
  let parseErrors = 0;
  const attachments = { signature: 0, manifest: 0, pubkey: 0, timestamp: 0, other: 0 };
  for (const file of files) {
    const lowerName = String(file?.name || '').toLowerCase();
    const explicitShardName = lowerName.endsWith('.qcont');
    try {
      parsed.push(await parseQcontShardPreviewFile(file));
    } catch {
      if (explicitShardName) {
        parseErrors += 1;
      } else {
        attachments[classifyNonShardFile(file)]++;
      }
    }
  }

  if (!parsed.length) {
    return {
      state: 'unknown',
      ready: false,
      message: 'No valid .qcont shard files detected in the selected input.',
    };
  }

  const containerIds = new Set(parsed.map((item) => item.containerId));
  if (containerIds.size !== 1) {
    return {
      state: 'invalid',
      ready: false,
      message: 'Selected shards belong to different containers.',
    };
  }

  const policies = new Set(parsed.map((item) => item.authPolicyLevel));
  if (policies.size !== 1) {
    return {
      state: 'invalid',
      ready: false,
      message: 'Selected shards disagree on archive authenticity policy.',
    };
  }

  const base = parsed[0];
  const uniqueIndices = new Set(parsed.map((item) => item.shardIndex));
  const uniqueCount = uniqueIndices.size;
  const duplicateCount = parsed.length - uniqueCount;
  const ready = uniqueCount >= base.t;

  let message = ready
    ? `Ready: ${uniqueCount}/${base.n} unique shards selected (need >=${base.t}).`
    : `Insufficient: ${uniqueCount}/${base.n} unique shards selected (need >=${base.t}).`;
  message += ` Policy: ${base.authPolicyLevel}.`;

  if (duplicateCount > 0) {
    message += ` ${duplicateCount} duplicate shard(s) skipped.`;
  }
  if (parseErrors > 0) {
    message += ` ${parseErrors} unreadable shard file(s).`;
  }

  const verificationParts = [];
  if (attachments.signature > 0) verificationParts.push(`${attachments.signature} signature(s)`);
  if (attachments.manifest > 0) verificationParts.push(`${attachments.manifest} manifest`);
  if (attachments.pubkey > 0) verificationParts.push(`${attachments.pubkey} public key(s)`);
  if (attachments.timestamp > 0) verificationParts.push(`${attachments.timestamp} timestamp(s)`);
  if (verificationParts.length > 0) {
    message += ` Attachments: ${verificationParts.join(', ')}.`;
  }
  if (attachments.other > 0) {
    message += ` ${attachments.other} unrecognized file(s) skipped.`;
  }

  return {
    state: ready ? 'sufficient' : 'insufficient',
    ready,
    message,
    threshold: base.t,
  };
}
