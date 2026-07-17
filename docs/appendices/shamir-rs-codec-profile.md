# QVqcont-7 Shamir and Reed-Solomon codec profile

Status: normative current-format compatibility profile; incomplete conformance suite

Scope: the Shamir share encoding and `QV-RS-ErasureCodes-v1` fragment encoding
used by `QVqcont-7`. This appendix freezes observed wire behavior; neither the
npm package nor the vendored JavaScript file is itself a language-neutral
standard.

## 1. Parameter relationship

Let `n` be the total shard count, `k` the systematic data-fragment count, and
`m = n - k`. The current profile requires `2 <= k < n <= 255`, `n >= 5`, even `m`, and
defines:

```text
f = m / 2
t = k + f
```

`f` is the number of missing or invalid fragment bodies the current decoder can
correct. `t` is both the required Shamir threshold and the number of valid shard
bodies required for recovery. The current codec does **not** recover from an
arbitrary `k` fragment bodies.

## 2. Shamir share encoding

### 2.1 Field and polynomial

Each secret byte is shared independently in the polynomial-basis field
`GF(2^8)` with modulus

```text
p(x) = x^8 + x^4 + x^3 + x + 1   (0x11b)
```

Addition and subtraction are bytewise XOR. Multiplication and division use
`0xe5` as the multiplicative generator. These parameters reproduce
`shamir-secret-sharing@0.0.4`; they are not implied by the name “Shamir”.

For secret byte `s_b` and threshold `t`, the dealer draws `t-1` independent
uniform bytes and constructs coefficients in ascending degree order:

```text
F_b(X) = s_b + a[b,1] X + ... + a[b,t-1] X^(t-1)
```

Zero random coefficients, including a zero highest coefficient, are permitted.
Evaluation uses Horner's rule from the highest coefficient down to the constant.

### 2.2 Randomness and coordinates

The dependency consumes randomness in this exact order:

1. Initialize `C[i] = i + 1` for `i = 0..254`.
2. Draw 255 bytes `R[0..254]`.
3. In increasing `i`, swap `C[i]` and `C[R[i] mod 255]`.
4. Use `C[0..n-1]` as the share coordinates in output-share order.
5. In increasing secret-byte order, draw `t-1` coefficient bytes for that
   byte before proceeding to the next byte.

The shuffle is biased because random values `0` and `255` both select index
zero. It nevertheless produces distinct coordinates in `1..255`; coordinate
randomization is not a Shamir secrecy requirement. New implementations MUST
reproduce this procedure when deterministic dealer-byte compatibility matters.

### 2.3 Wire order and combination

For a secret of `L` bytes, share `j` is exactly `L+1` bytes:

```text
F_0(x_j) || F_1(x_j) || ... || F_(L-1)(x_j) || x_j
```

The coordinate is the **final** byte, not the first byte. In the current
ML-KEM-1024 profile `L = 3168`, so a share is exactly 3169 bytes. The outer
zero-based `shardIndex` is not the Shamir coordinate.

Combination requires equal-length shares, final-byte coordinates in `1..255`,
and unique coordinates. For every secret-byte position it performs Lagrange
interpolation at `X = 0`. The low-level interpolation API has no threshold
parameter; `QVqcont-7` MUST supply exactly `t` commitment-valid shares (the
current implementation chooses the first `t` in outer shard-index order).
Coordinate zero and duplicate coordinates MUST be rejected before interpolation.

The SHA3-512 share commitments bind the complete raw share, including the final
coordinate. They are dealer commitments, not verifiable secret sharing and not
proof that the dealer used independent random coefficients.

## 3. Reed-Solomon fragment encoding

### 3.1 Field and shortened block geometry

The vendored codec is `public/third-party/erasure.js` with pinned SHA-256
`83a5c2789808cc4f0236e3d184cc160a0e995f105094d844c0fe813bab069c3d`.
It uses polynomial-basis `GF(2^8)` with

```text
p(x) = x^8 + x^4 + x^3 + x^2 + 1   (0x11d)
alpha = 0x02
```

For the current fixed maximum codeword value `B = 255`, define:

```text
s = floor(B / n)          bytes per shard symbol group
N = s * n                 encoded bytes per block
D = s * k                 input bytes per block
E = N - D = s * (n-k)     parity bytes per block
```

`N` is the current shortened codeword length. The implementation does not build
a Vandermonde or Cauchy generator matrix. Its normative construction is the
polynomial encoder below.

### 3.2 Systematic polynomial encoder

Coefficients are stored from highest to lowest degree. The generator polynomial
is

```text
g(Z) = product(i = 0..E-1) (Z + alpha^i)
```

For each full `D`-byte input block, initialize `W = input || zero(E)`. In
increasing input position `i`, let `c = W[i]`; when `c != 0`, XOR
`c * g[j]` into `W[i+j]` for every generator coefficient. Restore the original
input bytes in `W[0..D-1]` after division. The resulting systematic codeword is
the `D` input bytes followed by the `E` remainder bytes.

Before invoking the codec, `QVqcont-7` appends zero bytes to each encrypted QENC
chunk until its length is a multiple of `D`. Canonical shard production MUST use
that explicit padding and MUST NOT depend on the low-level dependency's
out-of-range-read behavior for a short final block.

### 3.3 Fragment order and framing

For every encoded block, fragment `j` receives the contiguous slice
`W[j*s .. (j+1)*s]`. Each shard concatenates its slice from successive blocks in
block order. Thus for ciphertext chunk length `C`:

```text
fragmentLength = ceil(C / D) * s
```

The shard body contains one record per QENC chunk, in QENC chunk order:

```text
uint32be(fragmentLength) || fragmentBytes
```

The stream MUST contain exactly the authenticated QENC `chunkCount` records and
end after the final fragment. Short, long, overflowing, or trailing records are
invalid inputs; they are not silently padded or truncated during restore.

### 3.4 Recovery semantics

For each block the decoder concatenates the `s` bytes from shard indices
`0..n-1`. A missing or commitment-invalid shard body is represented by an
all-zero `s`-byte slice. The vendored decoder computes `E` syndromes at
`alpha^0..alpha^(E-1)` and corrects these positions as unknown byte errors; it
does not consume known erasure locations.

The error bound is `E/2 = s*f` byte positions. One unavailable shard contributes
`s` positions per block, so at most `f` whole shard bodies may be unavailable.
Recovery therefore requires at least

```text
n - f = k + f = t
```

valid fragment bodies. Shamir-share validity and fragment-body validity are
independent: recovery needs at least `t` valid shares and no more than `f`
missing or invalid bodies.

After recombination, the implementation truncates explicit zero padding to the
authenticated ciphertext length, rebuilds the QENC container, strict-parses it,
and requires its SHA3-512 digest to equal the archive-state `qencHash`. That
digest is a mandatory backstop against decoder failure or a substituted runtime.

## 4. Dependency-copy limitations

- The vendored JavaScript decoder does not recheck that correction leaves zero
  syndromes. The Rust baseline does. QENC hash verification remains mandatory.
- The low-level JavaScript runtime does not by itself enforce equal or exact
  fragment lengths and may return a short result for truncated input. Exact
  authenticated fragment geometry MUST be validated before it is called, and
  its returned length MUST equal the requested ciphertext length.
- The low-level JavaScript splitter implicitly zero-fills some out-of-range reads
  for a short final block. `QVqcont-7` writers explicitly pad instead.
- Shamir and fragment commitments detect disagreement with the dealer's binding;
  they do not provide VSS, dealer-honesty evidence, proactive refresh, or
  cryptographic revocation.
- JavaScript arithmetic and memory handling have no constant-time or guaranteed
  erasure claim.

## 5. Known-answer evidence and remaining gates

`tests/core/shamir-rs-known-answer.test.mjs` contains:

- fixed 4-of-5 Shamir shares for secret `000001ff`, including coordinates `254`
  and `255`, derived from explicitly listed polynomials;
- rejection cases for coordinate zero and duplicate coordinates;
- the exact five SHA3-512 fragment hashes for the pinned Rust
  `n=5, k=3, f=1` vector over input bytes `0..153`;
- round-trip and one-/two-fragment corruption behavior;
- an explicit demonstration that the low-level JavaScript runtime is not a
  framing validator.

The Shamir shares were accepted by every 4-of-5 subset in both this checkout and
the Rust baseline at commit `f29f0905d88118858b44a6c71a355291544f3e97`. The RS
hashes are copied from that baseline's `erasure_malformed.rs` test and recomputed
by the integrity-checked vendored JavaScript runtime.

This is only a partial FMT-202 result. It does not yet provide vectors for every
supported tuple, deterministic cross-language dealer-output vectors, independent
third-party vectors, or differential fuzzing. INT-201 also remains open: copied
oracle values and a one-time local Rust probe are not live bidirectional
JavaScript-to-Rust CI.
