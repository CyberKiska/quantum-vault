export function validateRsParams(n, k) {
    if (!Number.isInteger(n) || !Number.isInteger(k)) return false;
    if (k < 2 || n <= k) return false;
    if ((n - k) % 2 !== 0) return false;
    if (n < 5) return false;
    return true;
}

export function calculateShamirThreshold(n, k) {
    return k + ((n - k) / 2);
}
