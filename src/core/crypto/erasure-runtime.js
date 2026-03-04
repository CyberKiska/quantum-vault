// Resolve the Reed-Solomon runtime for core sharding logic.
// Core stays UI-agnostic by depending on globalThis/injection.

export function resolveErasureRuntime(runtimeOverride = null) {
    const runtime = runtimeOverride ?? globalThis.erasure;
    if (!runtime?.split || !runtime?.recombine) {
        throw new Error('Reed-Solomon runtime (globalThis.erasure) is unavailable. Ensure erasure.js is loaded.');
    }
    return runtime;
}
