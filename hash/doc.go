/*
Package hash provides various hash algorithm encapsulations including MD5, SHA family, SM3, Murmur3, XXHash, and FNV algorithms.

The package offers both cryptographic and non-cryptographic hash functions, with a unified interface for common operations.
It includes implementations of secure hash algorithms (SHA-2, SM3) as well as fast non-cryptographic hashes (Murmur3, XXHash, FNV).

Exported Functions:
  - Md5([]byte) BytesResult: Calculates MD5 digest (not recommended for security purposes)
  - Sha1([]byte) BytesResult: Calculates SHA-1 digest (not recommended for security purposes)
  - Sha224([]byte) BytesResult: Calculates SHA-224 digest
  - Sha256([]byte) BytesResult: Calculates SHA-256 digest
  - Sha384([]byte) BytesResult: Calculates SHA-384 digest
  - Sha512([]byte) BytesResult: Calculates SHA-512 digest
  - Sm3([]byte) BytesResult: Calculates SM3 digest (Chinese national standard)
  - Murmur3([]byte) uint64: Calculates Murmur3 64-bit hash (non-cryptographic)
  - XXhash([]byte) []byte: Calculates XXHash digest (non-cryptographic)
  - XXHashUint64([]byte) uint64: Calculates XXHash 64-bit integer hash (non-cryptographic)
  - Fnv32([]byte) uint32: Calculates FNV-1a 32-bit hash (non-cryptographic)
  - Fnv64([]byte) uint64: Calculates FNV-1a 64-bit hash (non-cryptographic)
  - ByName(string) (HashFunc, error): Gets hash function by name
  - New(string) (*HashComparer, error): Creates a new hash comparer instance

Examples:
	// Calculate SHA-256 hash
	hashValue := hash.Sha256([]byte("hello world"))
	fmt.Printf("SHA-256: %x\n", hashValue.Bytes())

	// Use hash by name
	fn, err := hash.ByName("SHA256")
	if err != nil {
		log.Fatal(err)
	}
	result := fn([]byte("hello world"))

	// Use HashComparer for verification
	comparer, err := hash.New("SHA256")
	if err != nil {
		log.Fatal(err)
	}
	signature, _ := comparer.Sign([]byte("hello world"))
	isValid := comparer.Verify([]byte("hello world"), signature)

Security Warnings:
  - MD5: Broken (collision attacks exist), only for compatibility/non-security purposes
    (such as checksums, deduplication), prohibited for password storage, signatures, MAC, etc.
  - SHA1: Broken (collision attacks exist), only for compatibility/non-security purposes
    (such as checksums, deduplication), prohibited for password storage, signatures, MAC, etc.
*/
package hash