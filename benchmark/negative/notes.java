// Migration notes — no live crypto in this class. Every algorithm name below
// lives in a trailing comment, a block comment, or a prose string, so a precise
// scanner must not flag any of them (the naive line-regex baseline does).
public class Notes {
  int keySize = 2048; // formerly an RSA-2048 key, now ML-KEM

  /* Historically this class relied on RSA and ECDSA. The old MD5 and SHA-1
     checksums, plus the RC4 transport cipher, were all removed in the PQC
     migration. This is documentation, not usage. */
  void describe() {
    String note = "migrated off 3DES and ECDSA to AES-256 and Dilithium";
    throw new IllegalStateException("MD5 and RC4 are banned in this service");
  }
}
