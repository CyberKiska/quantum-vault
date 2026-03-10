const SUITE_REGISTRY = Object.freeze({
  'mldsa-44': {
    canonical: 'mldsa-44',
    displayName: 'ML-DSA-44',
    family: 'mldsa',
    strongPq: false,
    legacy: false,
    publicKeyType: 'ml-dsa-public-key',
  },
  'mldsa-65': {
    canonical: 'mldsa-65',
    displayName: 'ML-DSA-65',
    family: 'mldsa',
    strongPq: false,
    legacy: false,
    publicKeyType: 'ml-dsa-public-key',
  },
  'mldsa-87': {
    canonical: 'mldsa-87',
    displayName: 'ML-DSA-87',
    family: 'mldsa',
    strongPq: true,
    legacy: false,
    publicKeyType: 'ml-dsa-public-key',
  },
  'slhdsa-shake-128s': {
    canonical: 'slhdsa-shake-128s',
    displayName: 'SLH-DSA-SHAKE-128s',
    family: 'slhdsa-shake',
    strongPq: false,
    legacy: false,
    publicKeyType: 'slh-dsa-public-key',
  },
  'slhdsa-shake-192s': {
    canonical: 'slhdsa-shake-192s',
    displayName: 'SLH-DSA-SHAKE-192s',
    family: 'slhdsa-shake',
    strongPq: false,
    legacy: false,
    publicKeyType: 'slh-dsa-public-key',
  },
  'slhdsa-shake-256s': {
    canonical: 'slhdsa-shake-256s',
    displayName: 'SLH-DSA-SHAKE-256s',
    family: 'slhdsa-shake',
    strongPq: true,
    legacy: false,
    publicKeyType: 'slh-dsa-public-key',
  },
  'slhdsa-shake-256f': {
    canonical: 'slhdsa-shake-256f',
    displayName: 'SLH-DSA-SHAKE-256f',
    family: 'slhdsa-shake',
    strongPq: true,
    legacy: false,
    publicKeyType: 'slh-dsa-public-key',
  },
  ed25519: {
    canonical: 'ed25519',
    displayName: 'Ed25519',
    family: 'ed25519',
    strongPq: false,
    legacy: true,
    publicKeyType: 'ed25519-public-key',
  },
});

const ALIASES = Object.freeze({
  'ml-dsa-44': 'mldsa-44',
  'ml-dsa-65': 'mldsa-65',
  'ml-dsa-87': 'mldsa-87',
  mldsa44: 'mldsa-44',
  mldsa65: 'mldsa-65',
  mldsa87: 'mldsa-87',
  'slh-dsa-shake-128s': 'slhdsa-shake-128s',
  'slh-dsa-shake-192s': 'slhdsa-shake-192s',
  'slh-dsa-shake-256s': 'slhdsa-shake-256s',
  'slh-dsa-shake-256f': 'slhdsa-shake-256f',
});

function normalizeKey(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[_\s]+/g, '-');
}

export function normalizeSignatureSuite(value) {
  const normalized = normalizeKey(value);
  const canonical = ALIASES[normalized] || normalized;
  if (!SUITE_REGISTRY[canonical]) {
    throw new Error(`Unsupported signature suite: ${value}`);
  }
  return canonical;
}

export function getSignatureSuiteInfo(value) {
  return SUITE_REGISTRY[normalizeSignatureSuite(value)];
}

export function isStrongPqSuite(value) {
  return getSignatureSuiteInfo(value).strongPq === true;
}

export function listSupportedSignatureSuites() {
  return Object.keys(SUITE_REGISTRY);
}
