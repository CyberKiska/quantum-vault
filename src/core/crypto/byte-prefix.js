export function startsWithAscii(bytes, ascii) {
  if (!(bytes instanceof Uint8Array) || bytes.length < ascii.length) return false;
  for (let i = 0; i < ascii.length; i += 1) {
    if (bytes[i] !== ascii.charCodeAt(i)) return false;
  }
  return true;
}
