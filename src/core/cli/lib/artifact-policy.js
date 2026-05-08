export const FILE_MODE = Object.freeze({
  PUBLIC_ARTIFACT: 0o644,
  SECRET_ARTIFACT: 0o600,
});

export const READ_LIMIT = Object.freeze({
  SMALL_ARTIFACT_BYTES: 32 * 1024 * 1024,
});

export function smallArtifactReadOptions(label) {
  return {
    maxBytes: READ_LIMIT.SMALL_ARTIFACT_BYTES,
    label,
  };
}
