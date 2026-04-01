// --- Shared Crypto Constants ---

// Magic bytes for .qenc containers
// JS runtimes cannot Object.freeze() a non-empty Uint8Array directly, so keep the
// exported magic bytes sourced from a frozen numeric tuple.
export const MAGIC = Object.freeze([...new TextEncoder().encode('QVv1')]);

// Minimal valid container size sanity check (current format requires key commitment)
export const MINIMAL_CONTAINER_SIZE = 73; // MAGIC(4)+keyLen(4)+encap(1)+iv(12)+salt(16)+metaLen(2)+meta(1)+keyCommit(32)+ciphertext(1)

// AES/Chunking defaults
export const CHUNK_SIZE = 8 * 1024 * 1024; // 8 MiB
export const KDF_DOMAIN_V2 = 'quantum-vault:kdf:v2';
export const IV_DOMAIN_V2 = 'quantum-vault:chunk-iv:v2';
export const KENC_DOMAIN_V2 = 'quantum-vault:kenc:v2';
export const KIV_DOMAIN_V2 = 'quantum-vault:kiv:v2';

// Key commitment (SHA3-256 of Kenc) size in bytes
export const KEY_COMMITMENT_SIZE = 32;

// Current container format version
export const FORMAT_VERSION = 'QVv1-5-0';

// Current shard format version
export const QCONT_FORMAT_VERSION = 'QVqcont-6';
export const LEGACY_QCONT_FORMAT_VERSION = 'QVqcont-5';

// Archive authenticity policy defaults
export const LITE_DEFAULT_AUTH_POLICY_LEVEL = 'integrity-only';
export const PRO_DEFAULT_AUTH_POLICY_LEVEL = 'strong-pq-signature';
export const DEFAULT_ARCHIVE_AUTH_POLICY_LEVEL = PRO_DEFAULT_AUTH_POLICY_LEVEL;

// Maximum plaintext file size before allocation (1 GiB)
export const MAX_FILE_SIZE = 1024 * 1024 * 1024;
