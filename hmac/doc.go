/*
Package hmac implements Hash-based Message Authentication Code (HMAC) algorithms for message authentication.

HMAC uses cryptographic hash functions combined with a secret key to verify both the data integrity and authenticity of a message.
This package provides HMAC implementations based on various hash algorithms including MD5, SHA family, and SM3.

The package is designed to work in conjunction with the hash package, providing message authentication capabilities
using the same underlying hash algorithms.

Exported Functions:
  - Md5(key, msg []byte) Bytes: Calculates HMAC-MD5 authentication code
  - Sha1(key, msg []byte) Bytes: Calculates HMAC-SHA1 authentication code
  - Sha224(key, msg []byte) Bytes: Calculates HMAC-SHA224 authentication code
  - Sha256(key, msg []byte) Bytes: Calculates HMAC-SHA256 authentication code
  - Sha384(key, msg []byte) Bytes: Calculates HMAC-SHA384 authentication code
  - Sha512(key, msg []byte) Bytes: Calculates HMAC-SHA512 authentication code
  - Sm3(key, msg []byte) Bytes: Calculates HMAC-SM3 authentication code (Chinese national standard)
  - Md5From(key []byte, r io.Reader) (Bytes, error): Calculates HMAC-MD5 authentication code from a stream
  - Sha1From(key []byte, r io.Reader) (Bytes, error): Calculates HMAC-SHA1 authentication code from a stream
  - Sha224From(key []byte, r io.Reader) (Bytes, error): Calculates HMAC-SHA224 authentication code from a stream
  - Sha256From(key []byte, r io.Reader) (Bytes, error): Calculates HMAC-SHA256 authentication code from a stream
  - Sha384From(key []byte, r io.Reader) (Bytes, error): Calculates HMAC-SHA384 authentication code from a stream
  - Sha512From(key []byte, r io.Reader) (Bytes, error): Calculates HMAC-SHA512 authentication code from a stream
  - Sm3From(key []byte, r io.Reader) (Bytes, error): Calculates HMAC-SM3 authentication code from a stream
  - ByName(string) (HMacFunc, error): Gets HMAC function by name
  - New(string, []byte) (*HMacComparer, error): Creates an HMAC descriptor holding a private copy of the key;
    the descriptor exposes the MAC-semantics method set Digest(msg) (bytex.Bytes, error), Compare(msg, mac) bool,
    From(r io.Reader) (bytex.Bytes, error), CompareFrom(r io.Reader, mac []byte) (bool, error)
    and Hasher() hash.Hash
  - ErrZeroed: sentinel error returned by Digest/From/CompareFrom once the descriptor has been Zero()-ed
    (after Zero: Compare always returns false, Hasher panics)

Note on Digest: HMacComparer.Digest(msg) computes the HMAC of a whole message; it is unrelated to
the "append current digest" semantics of the standard library hash.Hash.Sum(b []byte).

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

	// Use HMacComparer for MAC calculation and verification
	comparer, err := hmac.New("HMACSHA256", key)
	if err != nil {
		log.Fatal(err)
	}
	mac, err := comparer.Digest(message)
	if err != nil {
		log.Fatal(err)
	}
	isValid := comparer.Compare(message, mac)

Streaming Computation:
	// 流式计算（适合大文件/大数据量，无需一次性读入内存）：
	// f, _ := os.Open("bigfile.bin")
	// defer f.Close()
	// mac, err := hmac.Sha256From(key, f)  // mac 为 bytex.Bytes

	// Streaming file MAC verification. Always check err before trusting the bool:
	// an IO failure must not be misread as an authentication failure. A Zero()-ed
	// descriptor reports ErrZeroed instead of degrading into a keyless comparison.
	f, err := os.Open("bigfile.bin")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	comparer, err := hmac.New("HMACSHA256", key)
	if err != nil {
		log.Fatal(err)
	}
	ok, err := comparer.CompareFrom(f, expectedMac)
	if err != nil {
		log.Fatal(err) // e.g. read error, or ErrZeroed if the descriptor was zeroed
	}
	fmt.Println("authenticated:", ok)

Concurrency:
  - All exported functions are pure or read from immutable registries, so they are
    safe to call concurrently from multiple goroutines. An HMacComparer descriptor is
    likewise shareable: Digest/Compare/From/CompareFrom/Hasher never mutate instance state and
    derive fresh objects—Hasher/From return a new incremental object per call—but
    never use the descriptor concurrently with Zero. The library deliberately
    provides no async/concurrent variants: goroutine ownership stays with the caller.
  - Offloading a call to a goroutine: the result channel MUST be buffered with
    capacity 1. If the context is cancelled while the computation is still running,
    the background goroutine can then deliver its result and exit, instead of
    blocking forever on an unbuffered send that nobody will ever receive (leak).

	select {
	case <-ctx.Done():
		return ctx.Err()
	case res := <-ch: // ch := make(chan result, 1); the worker sends exactly once
		return res.err
	}

  - Cancellation boundary: the stream API (Md5From ... Sm3From) reads via io.Copy,
    which does not observe context.Context. To stop mid-stream, wrap the reader so
    Read fails once the context is done:

	type ctxReader struct {
		ctx context.Context
		r   io.Reader
	}

	func (c *ctxReader) Read(p []byte) (int, error) {
		if err := c.ctx.Err(); err != nil {
			return 0, err
		}
		return c.r.Read(p)
	}

    Limitation: cancellation is only observed between Read calls; a blocked
    underlying reader (e.g. a stalled network connection) must itself be
    context-aware or closed to unblock io.Copy.
  - One pass, digest and MAC from the same bytes: HMacComparer.Hasher composes with
    io.MultiWriter (or io.TeeReader); each call derives a fresh incremental object:

	comparer, err := hmac.New("HMACSHA256", key)
	if err != nil {
		log.Fatal(err)
	}
	mac := comparer.Hasher()
	digest := sha256.New()
	if _, err := io.Copy(io.MultiWriter(digest, mac), r); err != nil {
		log.Fatal(err)
	}
	sum, macSum := digest.Sum(nil), mac.Sum(nil)

    Key lifecycle: New copies the key into the descriptor, and the standard
    library hmac.New derives the key into its ipad/opad state at construction
    time and never references the caller's slice—so the caller's key may be
    zeroed right after New returns. The objects returned by Hasher are
    security-equivalent to the key and must be protected accordingly; they are
    not safe for concurrent use—give every goroutine its own via a separate
    Hasher() call.
  - Keys and goroutines: sharing one key []byte for read-only HMAC calls across
    goroutines is safe. But Zero()/erasure must happen only after all goroutines
    are done, or each goroutine must hold its own copy (append([]byte(nil), key...)).
    In particular, never share a single HMacComparer instance between a goroutine
    calling Zero and others calling Digest/Compare/From/CompareFrom/Hasher.
  - FAQ: a single HMAC cannot be parallelized by splitting the message into
    blocks — the underlying hash is a chained compression function and the MAC
    depends on the complete message. Parallelism lives at the call level
    (independent HMACs of independent inputs), never inside one computation.

Security Notes:
  - HMAC's security doesn't rely on the collision resistance of the underlying hash (even though MD5 and SHA-1 have been collision-broken,
    HMAC-MD5 and HMAC-SHA1 still maintain pseudorandomness under standard assumptions)
  - However, for new code, prefer HMACSHA256 or HMACSM3 for better security margins
  - The security of HMAC depends on the secrecy of the key
  - Use sufficiently long and random keys (at least as long as the hash output)
*/
package hmac