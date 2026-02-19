// --- Shared Crypto Constants ---

// Magic bytes for .qenc containers
export const MAGIC = new TextEncoder().encode('QVv1');

// Minimal header size sanity check
export const MINIMAL_CONTAINER_SIZE = 38; // MAGIC(4) + keyLen(4) + iv(12) + salt(16) + metaLen(2)

// AES/Chunking defaults
export const CHUNK_SIZE = 8 * 1024 * 1024; // 8 MiB
export const KDF_DOMAIN_V1 = 'quantum-vault:kdf:v1';
export const IV_DOMAIN_V1 = 'quantum-vault:chunk-iv:v1';

// Key commitment (SHA3-256 of Kenc) size in bytes
export const KEY_COMMITMENT_SIZE = 32;

// Current container format version
export const FORMAT_VERSION = 'QVv1-4-0';

// Current shard format version
export const QCONT_FORMAT_VERSION = 'QVqcont-3';
