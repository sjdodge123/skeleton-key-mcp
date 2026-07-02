import { createRequire } from "node:module";
import type sodiumType from "libsodium-wrappers-sumo";

/**
 * We use the *sumo* build because the standard libsodium-wrappers omits the
 * argon2 password-hashing functions (crypto_pwhash*) we rely on. libsodium also
 * ships a broken ESM entry (its .mjs imports a sibling that isn't published), so
 * importing it directly fails under both Node ESM and vitest. Loading the CJS
 * build via createRequire sidesteps both problems. Import sodium from here.
 */
const require = createRequire(import.meta.url);
const sodium = require("libsodium-wrappers-sumo") as typeof sodiumType;

export default sodium;
