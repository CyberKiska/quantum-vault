import path from 'node:path';
import { startsWithAscii } from '../../crypto/byte-prefix.js';
import { bytesEqual, toHex } from '../../crypto/bytes.js';
import { parseOpenTimestampProof } from '../../crypto/auth/opentimestamps.js';
import { unpackPqpk, unpackQsig } from '../../crypto/auth/qsig.js';
import { isSupportedStellarSignatureDocumentBytes } from '../../crypto/auth/stellar-sig.js';
import { parseJsonBytesStrict } from '../../crypto/manifest/strict-json.js';
import { canonicalizeJson } from '../../crypto/manifest/jcs.js';
import { parseLifecycleShard, zeroizeParsedLifecycleShard } from '../../crypto/qcont/lifecycle-shard.js';
import { classifyJsonArtifactObject, digestSha3_512Hex } from '../lib/artifacts.js';
import { parseSingleFileCommandArgs } from '../lib/args.js';
import { readBytesFromFile } from '../lib/io.js';
import { ensureRuntimeCrypto } from '../lib/runtime.js';

function formatSuiteLabel(parsed) {
  if (typeof parsed?.suiteDisplay === 'string' && parsed.suiteDisplay) {
    return parsed.suiteDisplay;
  }
  if (typeof parsed?.suite === 'string' && parsed.suite) {
    return parsed.suite;
  }
  if (Number.isInteger(parsed?.suiteId)) {
    return `suiteId:${parsed.suiteId}`;
  }
  return 'unknown';
}

async function inspectJsonArtifact(bytes, filePath) {
  const rawObject = parseJsonBytesStrict(bytes);
  const descriptor = classifyJsonArtifactObject(rawObject);
  if (!descriptor) {
    throw new Error(`Unsupported JSON artifact for inspect: ${filePath}`);
  }
  const canonicalized = await descriptor.canonicalize(rawObject);
  return {
    command: 'inspect',
    file: filePath,
    artifactType: descriptor.artifactType,
    artifactVersion: descriptor.artifactVersion,
    encoding: 'json',
    digestAlg: 'SHA3-512',
    digestHex: canonicalized.digest.value,
    inputDigestHex: digestSha3_512Hex(bytes),
    canonicalInput: bytesEqual(bytes, canonicalized.bytes),
    canonicalJson: canonicalized[descriptor.objectField],
    canonicalJsonText: canonicalized.canonical,
  };
}

async function inspectBinaryArtifact(bytes, filePath) {
  const inputDigestHex = digestSha3_512Hex(bytes);

  if (startsWithAscii(bytes, 'QVC1')) {
    const parsed = await parseLifecycleShard(bytes, { strict: true });
    try {
      return {
        command: 'inspect',
        file: filePath,
        artifactType: 'QVqcont-7',
        artifactVersion: 'QVqcont-7',
        encoding: 'binary',
        digestAlg: 'SHA3-512',
        digestHex: inputDigestHex,
        canonicalJson: parsed.metaJSON,
        canonicalJsonText: canonicalizeJson(parsed.metaJSON),
        parsedSummary: {
          archiveId: parsed.archiveState.archiveId,
          stateId: parsed.stateId,
          cohortId: parsed.cohortId,
          shardIndex: parsed.shardIndex,
          archiveStateDigestHex: parsed.archiveStateDigestHex,
          cohortBindingDigestHex: parsed.cohortBindingDigestHex,
          lifecycleBundleDigestHex: parsed.lifecycleBundleDigestHex,
        },
      };
    } finally {
      zeroizeParsedLifecycleShard(parsed);
    }
  }

  if (startsWithAscii(bytes, 'PQSG')) {
    const parsed = unpackQsig(bytes);
    return {
      command: 'inspect',
      file: filePath,
      artifactType: '.qsig',
      artifactVersion: `v${parsed.versionMajor}.${parsed.versionMinor}`,
      encoding: 'binary',
      digestAlg: 'SHA3-512',
      digestHex: inputDigestHex,
      parsedSummary: {
        suite: formatSuiteLabel(parsed),
        suiteId: parsed.suiteId,
        context: parsed.ctx,
        payloadDigestAlg: 'SHA3-512',
        payloadDigestHex: toHex(parsed.payloadDigest),
        authMetaDigestAlg: 'SHA3-256',
        authMetaDigestHex: toHex(parsed.authMetaDigest),
        signatureLength: parsed.signatureLength,
        signerFingerprintHex: parsed.signerFingerprint ? toHex(parsed.signerFingerprint) : null,
        embeddedSignerPublicKey: parsed.metadata?.signerPublicKey instanceof Uint8Array,
      },
    };
  }

  if (startsWithAscii(bytes, 'PQPK')) {
    const parsed = unpackPqpk(bytes);
    return {
      command: 'inspect',
      file: filePath,
      artifactType: '.pqpk',
      artifactVersion: `v${parsed.versionMajor}.${parsed.versionMinor}`,
      encoding: 'binary',
      digestAlg: 'SHA3-512',
      digestHex: inputDigestHex,
      parsedSummary: {
        suite: formatSuiteLabel(parsed),
        suiteId: parsed.suiteId,
        keyLength: parsed.keyBytes.length,
        crc32Verified: true,
      },
    };
  }

  try {
    const parsed = parseOpenTimestampProof(bytes, { name: path.basename(filePath) });
    return {
      command: 'inspect',
      file: filePath,
      artifactType: '.ots',
      artifactVersion: 'OpenTimestamps-proof-v1',
      encoding: 'binary',
      digestAlg: 'SHA3-512',
      digestHex: inputDigestHex,
      parsedSummary: {
        stampedDigestAlg: 'SHA-256',
        stampedDigestHex: parsed.stampedDigestHex,
        apparentlyComplete: parsed.appearsComplete === true,
        completeProof: parsed.completeProof === true,
      },
    };
  } catch {
    // Continue.
  }

  if (isSupportedStellarSignatureDocumentBytes(bytes)) {
    const parsed = parseJsonBytesStrict(bytes);
    return {
      command: 'inspect',
      file: filePath,
      artifactType: '.sig',
      artifactVersion: 'stellar-detached-signature-v1',
      encoding: 'json',
      digestAlg: 'SHA3-512',
      digestHex: inputDigestHex,
      parsedSummary: {
        signer: typeof parsed?.signer === 'string' ? parsed.signer : null,
        hasSignedXdr: typeof parsed?.signedXdr === 'string' && parsed.signedXdr.length > 0,
        hasSep53Signature: typeof parsed?.signatureB64 === 'string' && parsed.signatureB64.length > 0,
      },
    };
  }

  throw new Error(`Unsupported artifact for inspect: ${filePath}`);
}

async function inspectArtifact(bytes, filePath) {
  try {
    return await inspectJsonArtifact(bytes, filePath);
  } catch (error) {
    if (!String(error?.message || error).startsWith('Unsupported JSON artifact')) {
      if (!(error instanceof Error) || !/JSON/.test(error.message)) {
        throw error;
      }
    }
  }
  return inspectBinaryArtifact(bytes, filePath);
}

export function parseInspectArgs(args) {
  return parseSingleFileCommandArgs('inspect', args);
}

export async function runInspectCommand(filePath) {
  await ensureRuntimeCrypto();
  const bytes = await readBytesFromFile(filePath);
  try {
    return await inspectArtifact(bytes, filePath);
  } finally {
    bytes.fill(0);
  }
}

export function renderInspectSummary(report) {
  const lines = [
    `File: ${report.file}`,
    `Type: ${report.artifactType}`,
    `Version: ${report.artifactVersion}`,
    `SHA3-512: ${report.digestHex}`,
  ];
  if (typeof report.canonicalInput === 'boolean') {
    lines.push(`Canonical input: ${report.canonicalInput ? 'yes' : 'no'}`);
  }
  if (report.canonicalJsonText) {
    lines.push('');
    lines.push(report.canonicalJsonText);
  } else if (report.parsedSummary) {
    lines.push('');
    lines.push(JSON.stringify(report.parsedSummary, null, 2));
  }
  return `${lines.join('\n')}\n`;
}
