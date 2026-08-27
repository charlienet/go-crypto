/*
Package hmac implements Hash-based Message Authentication Code (HMAC) algorithms for message authentication.

HMAC uses cryptographic hash functions combined with a secret key to verify both the data integrity and authenticity of a message.
This package provides HMAC implementations based on various hash algorithms including MD5, SHA family, and SM3.

The package is designed to work in conjunction with the hash package, providing message authentication capabilities
using the same underlying hash algorithms.

Exported Functions:
  - Md5(key, msg []byte) BytesResult: Calculates HMAC-MD5 authentication code
  - Sha1(key, msg []byte) BytesResult: Calculates HMAC-SHA1 authentication code
  - Sha224(key, msg []byte) BytesResult: Calculates HMAC-SHA224 authentication code
  - Sha256(key, msg []byte) BytesResult: Calculates HMAC-SHA256 authentication code
  - Sha384(key, msg []byte) BytesResult: Calculates HMAC-SHA384 authentication code
  - Sha512(key, msg []byte) BytesResult: Calculates HMAC-SHA512 authentication code
  - Sm3(key, msg []byte) BytesResult: Calculates HMAC-SM3 authentication code (Chinese national standard)
  - ByName(string) (HMacFunc, error): Gets HMAC function by name
  - New(string, []byte) (*HMacComparer, error): Creates a new HMAC comparer instance with the specified algorithm and key

Examples:
	// Calculate HMAC-SHA256
	key := []byte("my-secret-key")
	message := []byte("hello world")
	hmacValue := hmac.Sha256(key, message)
	fmt.Printf("HMAC-SHA256: %x\n", hmacValue.Bytes())

	// Use HMAC by name
	fn, err := hmac.ByName("HMACSHA256")
	if err != nil {
		log.Fatal(err)
	}
	result := fn(key, message)

	// Use HMacComparer for verification
	comparer, err := hmac.New("HMACSHA256", key)
	if err != nil {
		log.Fatal(err)
	}
	signature, _ := comparer.Sign(message)
	isValid := comparer.Verify(message, signature)

Security Notes:
  - HMAC's security doesn't rely on the collision resistance of the underlying hash (even though MD5 and SHA-1 have been collision-broken,
    HMAC-MD5 and HMAC-SHA1 still maintain pseudorandomness under standard assumptions)
  - However, for new code, prefer HMACSHA256 or HMACSM3 for better security margins
  - The security of HMAC depends on the secrecy of the key
  - Use sufficiently long and random keys (at least as long as the hash output)
*/
package hmac