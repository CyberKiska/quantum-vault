import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { digestSha256, toHex } from '../../crypto/bytes.js';
import { MAX_FILE_SIZE } from '../../crypto/constants.js';

const STREAM_YIELD_BYTES = 8 * 1024 * 1024; // Bytes read or hashed before yielding to the event loop

async function readWholeBlobAsUint8Array(blob) {
  if (blob.size === 0) {
    return new Uint8Array(0);
  }
  const out = new Uint8Array(blob.size);
  let offset = 0;
  let sinceYield = 0;

  if (typeof blob.stream === 'function') {
    const reader = blob.stream().getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        out.set(value, offset);
        offset += value.byteLength;
        sinceYield += value.byteLength;
        if (sinceYield >= STREAM_YIELD_BYTES) {
          sinceYield = 0;
          await new Promise((resolve) => {
            setTimeout(resolve, 0);
          });
        }
      }
    } finally {
      reader.releaseLock?.();
    }
  } else {
    const chunkSize = 4 * 1024 * 1024;
    for (let pos = 0; pos < blob.size; pos += chunkSize) {
      const end = Math.min(pos + chunkSize, blob.size);
      const buf = await blob.slice(pos, end).arrayBuffer();
      const chunk = new Uint8Array(buf);
      out.set(chunk, offset);
      offset += chunk.byteLength;
      sinceYield += chunk.byteLength;
      if (sinceYield >= STREAM_YIELD_BYTES) {
        sinceYield = 0;
        await new Promise((resolve) => {
          setTimeout(resolve, 0);
        });
      }
    }
  }

  if (offset !== blob.size) {
    throw new Error('Incomplete file read while hashing.');
  }
  return out;
}

function createSha3Hasher(alg) {
  if (alg === 'SHA3-512') return sha3_512.create();
  if (alg === 'SHA3-256') return sha3_256.create();
  throw new Error(`Unsupported digest algorithm "${alg}" for file hashing.`);
}

async function hashBlobSha256WebCrypto(blob) {
  const bytes = await readWholeBlobAsUint8Array(blob);
  return toHex(await digestSha256(bytes));
}

async function hashBlobSha3Streaming(blob, alg) {
  const hasher = createSha3Hasher(alg);
  let sinceYield = 0;

  if (typeof blob.stream === 'function') {
    const reader = blob.stream().getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        hasher.update(value);
        sinceYield += value.byteLength;
        if (sinceYield >= STREAM_YIELD_BYTES) {
          sinceYield = 0;
          await new Promise((resolve) => {
            setTimeout(resolve, 0);
          });
        }
      }
    } finally {
      reader.releaseLock?.();
    }
  } else {
    const chunkSize = 4 * 1024 * 1024;
    for (let offset = 0; offset < blob.size; offset += chunkSize) {
      const end = Math.min(offset + chunkSize, blob.size);
      const slice = blob.slice(offset, end);
      const buf = await slice.arrayBuffer();
      const bytes = new Uint8Array(buf);
      if (bytes.byteLength > 0) {
        hasher.update(bytes);
      }
      sinceYield += bytes.byteLength;
      if (sinceYield >= STREAM_YIELD_BYTES) {
        sinceYield = 0;
        await new Promise((resolve) => {
          setTimeout(resolve, 0);
        });
      }
    }
  }

  return toHex(hasher.digest());
}

// Hash raw file bytes with the algorithm selected for a source-evidence digest row

export async function hashBlobForSourceDigestAlg(blob, alg) {
  if (!(blob instanceof Blob)) {
    throw new Error('Expected a file or blob to hash.');
  }
  if (blob.size > MAX_FILE_SIZE) {
    throw new Error(`File exceeds maximum size (${MAX_FILE_SIZE} bytes).`);
  }

  if (alg === 'SHA-256') {
    return hashBlobSha256WebCrypto(blob);
  }
  return hashBlobSha3Streaming(blob, alg);
}
