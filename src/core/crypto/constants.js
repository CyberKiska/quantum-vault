// --- Shared Crypto Constants ---

// Magic bytes for .qenc containers
export const MAGIC = new TextEncoder().encode('QVv1');

// Minimal header size sanity check
export const MINIMAL_CONTAINER_SIZE = 38; // MAGIC(4) + keyLen(4) + iv(12) + salt(16) + metaLen(2)

// AES/Chunking defaults
export const CHUNK_SIZE = 8 * 1024 * 1024; // 8 MiB
export const DEFAULT_CUSTOMIZATION = 'QuantumVault v1.3.1';
