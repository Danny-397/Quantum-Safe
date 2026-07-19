// Logging + error strings only — the crypto names here are messages, not usage.
export function guard(alg) {
  console.log("Do not use ECDSA or RSA for new keys"); // legacy guidance
  if (alg === "banned") {
    throw new Error("MD5 and RC4 are disabled"); // was 3DES too
  }
  /* Block comment: this module dropped SHA-1 and Diffie-Hellman long ago. */
  const label = "TLSv1 support was removed; use TLS 1.3";
  return label;
}
