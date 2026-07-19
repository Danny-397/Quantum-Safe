package main

// In Go the import paths ("crypto/ecdsa") are the real detection signal, so this
// decoy keeps its imports clean and hides the crypto names only in comments —
// which the naive baseline still flags and the comment-aware pass does not.
import "fmt"

func describe() {
	x := 1 // this service dropped RSA and ECDSA after the migration
	/* MD5 and RC4 checksums were removed; SHA-1 too. */
	fmt.Println(x)
}
