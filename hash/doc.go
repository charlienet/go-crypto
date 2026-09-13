/*
Package hash provides various hash algorithm encapsulations including MD5, SHA family, SM3, Murmur3, XXHash, and FNV algorithms.

The package offers both cryptographic and non-cryptographic hash functions, with a unified interface for common operations.
It includes implementations of secure hash algorithms (SHA-2, SM3) as well as fast non-cryptographic hashes (Murmur3, XXHash, FNV).

Exported Functions:
  - Md5([]byte) Bytes: Calculates MD5 digest (not recommended for security purposes)
  - Sha1([]byte) Bytes: Calculates SHA-1 digest (not recommended for security purposes)
  - Sha224([]byte) Bytes: Calculates SHA-224 digest
  - Sha256([]byte) Bytes: Calculates SHA-256 digest
  - Sha384([]byte) Bytes: Calculates SHA-384 digest
  - Sha512([]byte) Bytes: Calculates SHA-512 digest
  - Sm3([]byte) Bytes: Calculates SM3 digest (Chinese national standard)
  - Murmur3([]byte) uint64: Calculates Murmur3 64-bit hash (non-cryptographic)
  - XXhash([]byte) []byte: Calculates XXHash digest (non-cryptographic)
  - XXHashUint64([]byte) uint64: Calculates XXHash 64-bit integer hash (non-cryptographic)
  - Fnv32([]byte) uint32: Calculates FNV-1a 32-bit hash (non-cryptographic)
  - Fnv64([]byte) uint64: Calculates FNV-1a 64-bit hash (non-cryptographic)
  - Md5From(io.Reader) (Bytes, error): Streaming MD5 digest (not recommended for security purposes)
  - Sha1From(io.Reader) (Bytes, error): Streaming SHA-1 digest (not recommended for security purposes)
  - Sha224From(io.Reader) (Bytes, error): Streaming SHA-224 digest
  - Sha256From(io.Reader) (Bytes, error): Streaming SHA-256 digest
  - Sha384From(io.Reader) (Bytes, error): Streaming SHA-384 digest
  - Sha512From(io.Reader) (Bytes, error): Streaming SHA-512 digest
  - Sm3From(io.Reader) (Bytes, error): Streaming SM3 digest (Chinese national standard)
  - Murmur3From(io.Reader) (uint64, error): Streaming Murmur3 64-bit hash (non-cryptographic)
  - XXhashFrom(io.Reader) ([]byte, error): Streaming XXHash digest (non-cryptographic)
  - XXHashUint64From(io.Reader) (uint64, error): Streaming XXHash 64-bit integer hash (non-cryptographic)
  - Fnv32From(io.Reader) (uint32, error): Streaming FNV-1a 32-bit hash (non-cryptographic)
  - Fnv64From(io.Reader) (uint64, error): Streaming FNV-1a 64-bit hash (non-cryptographic)
  - ByName(string) (HashFunc, error): Gets a one-shot digest function by algorithm name (derived from the constructor registry)
  - New(string) (*HashComparer, error): Creates a stateless hash descriptor whose methods are: Digest(msg) for one-shot digests, Compare(msg, target) for constant-time digest comparison, From(reader) for streaming digests, CompareFrom(reader, target) for streaming constant-time comparison, and Hasher() for a fresh standard-library incremental hash.Hash

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

	// Use the HashComparer descriptor: one-shot digest + constant-time compare
	comparer, err := hash.New("SHA256")
	if err != nil {
		log.Fatal(err)
	}
	digest := comparer.Digest([]byte("hello world")) // no error: hashing never fails
	isValid := comparer.Compare([]byte("hello world"), digest.Bytes())

	// 流式计算（适合大文件/大数据量，无需一次性读入内存）：
	// f, _ := os.Open("bigfile.bin")
	// defer f.Close()
	// d, err := hash.Sha256From(f)  // d 为 bytex.Bytes

	// Streaming integrity check of a large file (no full read into memory):
	// the descriptor derives a fresh hasher per call, so one instance can be
	// shared across goroutines. Always check err BEFORE trusting the bool:
	// on a read failure CompareFrom returns (false, err), and ignoring err
	// would misreport an IO fault as "verification failed".
	//
	// c, _ := hash.New("SHA256")
	// f, err := os.Open("bigfile.bin")
	// if err != nil { ... }
	// defer f.Close()
	// ok, err := c.CompareFrom(f, want)
	// if err != nil {
	// 	return err // IO error: the comparison never actually happened
	// }
	// if !ok {
	// 	return errors.New("digest mismatch")
	// }

Security Warnings:
  - MD5: Broken (collision attacks exist), only for compatibility/non-security purposes
    (such as checksums, deduplication), prohibited for password storage, signatures, MAC, etc.
  - SHA1: Broken (collision attacks exist), only for compatibility/non-security purposes
    (such as checksums, deduplication), prohibited for password storage, signatures, MAC, etc.

Concurrency:
All exported functions (Xxx, XxxFrom, ByName, New) are pure functions
or read-only registry lookups with no shared mutable state, and are safe for
concurrent use by multiple goroutines. The *HashComparer descriptor is itself
read-only (it only holds a constructor): one instance may be shared freely
across goroutines, while every Hasher()/From call derives a fresh object.
Note that Digest(msg) computes a digest from a complete message and is
unrelated to the appending semantics of the standard library's
hash.Hash.Sum(b []byte). Goroutine ownership always stays with
the caller: this package deliberately provides no async/concurrent variants.

	// Idiomatic caller-side goroutine wrapper (note the channel buffered with
	// size 1: even after ctx is canceled and this function returns early, the
	// background goroutine can still send its result and exit, so it never
	// leaks; errors travel back through the return value):
	//
	// type digestResult struct {
	// 	sum bytex.Bytes
	// 	err error
	// }
	// func sha256File(ctx context.Context, path string) (bytex.Bytes, error) {
	// 	ch := make(chan digestResult, 1) // buffer size 1: see comment above
	// 	go func() {
	// 		f, err := os.Open(path)
	// 		if err != nil {
	// 			ch <- digestResult{err: err}
	// 			return
	// 		}
	// 		defer f.Close()
	// 		sum, err := hash.Sha256From(f)
	// 		ch <- digestResult{sum: sum, err: err}
	// 	}()
	// 	select {
	// 	case <-ctx.Done():
	// 		return nil, ctx.Err()
	// 	case res := <-ch:
	// 		return res.sum, res.err
	// 	}
	// }

	Cancellation boundary: io.Copy (used by all XxxFrom functions) does not
	respond to context. To stop a stream mid-way, the reader itself must be
	context-aware:

		// ctxReader stops reads once ctx is canceled. Limitation: it cannot
		// interrupt a Read call that is already blocked inside the underlying
		// reader; for network readers you still need Close() or
		// SetReadDeadline() to unblock the pending syscall.
		type ctxReader struct {
			ctx context.Context
			r   io.Reader
		}

		func (c *ctxReader) Read(p []byte) (int, error) {
			select {
			case <-c.ctx.Done():
				return 0, c.ctx.Err()
			default:
				return c.r.Read(p)
			}
		}

	// Use it as: hash.Sha256From(&ctxReader{ctx: ctx, r: raw})

One read, multiple digests: combine New(...).Hasher() with io.MultiWriter
(e.g. dual-track compliance requires SHA-256 and SM3 over the same data at once):

	c1, _ := hash.New("SHA256")
	c2, _ := hash.New("SM3")
	h1, h2 := c1.Hasher(), c2.Hasher()
	f, _ := os.Open("bigfile.bin")
	defer f.Close()
	_, err := io.Copy(io.MultiWriter(h1, h2), f) // single pass over the file
	digest1 := h1.Sum(nil)
	digest2 := h2.Sum(nil)

The hash.Hash values returned by Hasher() hold incremental state and are NOT
goroutine-safe: in concurrent scenarios each goroutine must call Hasher() to
build its own instance; never share one hash.Hash across goroutines.

Frequently asked: can a single SHA-2/SM3 digest be computed faster by splitting
the input into blocks and hashing them in parallel? No. These algorithms use
Merkle-Damgard chained compression, where each block depends on the state of
all previous blocks, so one digest is inherently sequential. This package does
not include tree hashing.
*/
package hash
