package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"
	"hash/fnv"
	"strings"

	"github.com/cespare/xxhash/v2"
	"github.com/charlienet/go-utils/bytesconv"
	"github.com/charlienet/go-crypto"
	"github.com/emmansun/gmsm/sm3"
	"github.com/spaolacci/murmur3"
)

var _ crypto.Signer = &HashComparer{}

type HashFunc func([]byte) bytesconv.BytesResult

var hashFuncs = map[string]HashFunc{
	"MD5":    Md5,
	"SHA1":   Sha1,
	"SHA224": Sha224,
	"SHA256": Sha256,
	"SHA384": Sha384,
	"SHA512": Sha512,
	"SM3":    Sm3,
}

type HashComparer struct {
	hashFunc HashFunc
}

func New(fname string) (*HashComparer, error) {
	f, err := ByName(fname)
	if err != nil {
		return nil, err
	}

	return &HashComparer{
		hashFunc: f,
	}, nil
}

func (c *HashComparer) Sign(msg []byte) (bytesconv.BytesResult, error) {
	ret := c.hashFunc(msg)
	return ret.Bytes(), nil
}

func (c *HashComparer) Verify(msg, target []byte) bool {
	ret := c.hashFunc(msg)

	// 长度不等直接返回 false，避免进入常量时间比较
	if len(target) != len(ret.Bytes()) {
		return false
	}

	// 使用常量时间比较，避免通过比较时间逐字节猜测摘要
	return subtle.ConstantTimeCompare(ret.Bytes(), target) == 1
}

func ByName(name string) (HashFunc, error) {
	if f, ok := hashFuncs[strings.ToUpper(name)]; ok {
		return f, nil
	}

	return nil, fmt.Errorf("unsupported hash function %q, supported: md5, sha1, sha224, sha256, sha384, sha512, sm3", name)
}

// Deprecated: MD5 已不安全，不应用于安全场景。仅用于兼容性。
// Md5 计算消息的 MD5 摘要。
//
// 警告：MD5 已被破解（存在碰撞攻击），仅限兼容/非安全用途
// （如校验和、去重），禁止用于密码存储、签名、MAC 等安全场景。
func Md5(msg []byte) bytesconv.BytesResult { return sum(md5.New, msg) }

// Deprecated: SHA1 已不安全，不应用于安全场景。仅用于兼容性。
// Sha1 计算消息的 SHA-1 摘要。
//
// 警告：SHA-1 已被破解（存在碰撞攻击），仅限兼容/非安全用途
// （如校验和、去重），禁止用于密码存储、签名、MAC 等安全场景。
func Sha1(msg []byte) bytesconv.BytesResult { return sum(sha1.New, msg) }

func Sha224(msg []byte) bytesconv.BytesResult { return sum(sha256.New224, msg) }

func Sha256(msg []byte) bytesconv.BytesResult { return sum(sha256.New, msg) }

func Sha384(msg []byte) bytesconv.BytesResult { return sum(sha512.New384, msg) }

func Sha512(msg []byte) bytesconv.BytesResult { return sum(sha512.New, msg) }

func Sm3(msg []byte) bytesconv.BytesResult { return sum(sm3.New, msg) }

// Murmur3 计算消息的 Murmur3 64 位哈希。
//
// 注意：非加密哈希，仅用于哈希表、分片、去重、负载均衡等非安全场景，
// 禁止用于安全校验、MAC、密码存储或任何对抗性输入场景。
func Murmur3(msg []byte) uint64 {
	return murmur3.Sum64(msg)
}

// XXhash 计算消息的 xxhash 摘要（64 位，返回 8 字节）。
//
// 注意：非加密哈希，仅用于哈希表、分片、去重、负载均衡等非安全场景，
// 禁止用于安全校验、MAC、密码存储或任何对抗性输入场景。
func XXhash(msg []byte) []byte {
	d := xxhash.New()
	_, _ = d.Write(msg)
	return d.Sum(nil)
}

// XXHashUint64 计算消息的 xxhash 64 位整型哈希。
//
// 注意：非加密哈希，仅用于哈希表、分片、去重、负载均衡等非安全场景，
// 禁止用于安全校验、MAC、密码存储或任何对抗性输入场景。
func XXHashUint64(msg []byte) uint64 {
	h := xxhash.New()
	_, _ = h.Write(msg)
	return h.Sum64()
}

// Fnv32 计算消息的 FNV-1a 32 位哈希。
//
// 注意：非加密哈希，仅用于哈希表、分片、去重、负载均衡等非安全场景，
// 禁止用于安全校验、MAC、密码存储或任何对抗性输入场景。
func Fnv32(msg []byte) uint32 {
	h := fnv.New32()
	_, _ = h.Write(msg)
	return h.Sum32()
}

// Fnv64 计算消息的 FNV-1a 64 位哈希。
//
// 注意：非加密哈希，仅用于哈希表、分片、去重、负载均衡等非安全场景，
// 禁止用于安全校验、MAC、密码存储或任何对抗性输入场景。
func Fnv64(msg []byte) uint64 {
	h := fnv.New64()
	_, _ = h.Write(msg)
	return h.Sum64()
}



func sum(f func() hash.Hash, msg []byte) bytesconv.BytesResult {
	h := f()

	_, _ = h.Write(msg)
	return h.Sum(nil)
}
