package hash_test

import (
	"testing"

	"github.com/charlienet/go-crypto/hash"
)

func TestHash(t *testing.T) {
	t.Log(hash.SHA256.Sum([]byte("abc")).Hex())
	t.Log(hash.SHA256.Sum([]byte("abc")).Base64())
	t.Log(hash.SM3.Sum([]byte("abc")).Hex())
}

func TestHMac(t *testing.T) {
	t.Log(hash.SM3.HMAC([]byte("abc")).Sum([]byte("abc")).Hex())
	t.Log(hash.SHA256.HMAC([]byte("123456")).Sum([]byte("sample message")).Hex())
}

func BenchmarkHash64(b *testing.B) {
	key := []byte("abc")
	b.Run("Funv64", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			hash.Funv64(key)
		}
	})

	b.Run("Murmur3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			hash.Murmur3(key)
		}
	})

	b.Run("xxhash", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			hash.XXHashUint64(key)
		}
	})
}
