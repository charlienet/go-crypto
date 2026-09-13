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
	"io"
	"strings"

	"github.com/cespare/xxhash/v2"
	"github.com/charlienet/go-utils/bytex"
	"github.com/emmansun/gmsm/sm3"
	"github.com/spaolacci/murmur3"
)

type HashFunc func([]byte) bytex.Bytes

// hashNewFuncs 是唯一的算法注册表：算法名 → 标准库增量哈希构造函数。
// 一次性版本（HashFunc）与描述器、增量对象均由它派生，新增算法只需注册一处。
var hashNewFuncs = map[string]func() hash.Hash{
	"MD5":    md5.New,
	"SHA1":   sha1.New,
	"SHA224": sha256.New224,
	"SHA256": sha256.New,
	"SHA384": sha512.New384,
	"SHA512": sha512.New,
	"SM3":    sm3.New,
}

// HashComparer 是哈希描述器：只持有构造函数，不持有增量状态，
// 因此本身并发安全、可长期复用；每次调用方法都会派生全新哈希对象。
type HashComparer struct {
	newFunc func() hash.Hash
}

func New(fname string) (*HashComparer, error) {
	f, err := newFuncByName(fname)
	if err != nil {
		return nil, err
	}
	return &HashComparer{newFunc: f}, nil
}

// Digest 对完整消息一次性求摘要。注意：这是「输入消息、输出摘要」，
// 与标准库 hash.Hash.Sum(b []byte) 的「把当前摘要追加到 b」语义无关，
// 需要标准库增量语义请用 Hasher()。
//
// 本方法不返回 error：哈希计算不会失败。
func (c *HashComparer) Digest(msg []byte) bytex.Bytes { return sum(c.newFunc, msg) }

// Compare 计算 msg 的摘要并与 target 做常量时间比较。
func (c *HashComparer) Compare(msg, target []byte) bool {
	return compareDigest(c.Digest(msg).Bytes(), target)
}

// compareDigest 对「已算好的摘要」与 target 做安全比较：先长度预检，
// 再用常量时间比较，避免通过比较耗时逐字节猜测摘要。
// 长度信息不泄露任何机密（摘要长度由算法固定），提前返回是安全的。
func compareDigest(got, target []byte) bool {
	if len(target) != len(got) {
		return false
	}
	return subtle.ConstantTimeCompare(got, target) == 1
}

// From 从 r 流式计算摘要，读取过程中的错误原样返回，出错时结果为 nil。
// 描述器本身无可变状态，可多协程并发调用。
func (c *HashComparer) From(r io.Reader) (bytex.Bytes, error) { return sumFrom(c.newFunc, r) }

// CompareFrom 从 r 流式计算摘要并与 target 做常量时间比较，适用于大文件、
// 网络流等不宜一次性读入内存的完整性校验场景。
//
// 与 Compare 不同，本方法带 error 返回：读取过程可能失败。出错时返回
// (false, err)，此时布尔值不携带任何校验信息，调用方必须先判断 err，
// 否则一次 IO 故障会被误读为「校验不通过」。
//
// 描述器无可变状态，可多协程并发调用。
func (c *HashComparer) CompareFrom(r io.Reader, target []byte) (bool, error) {
	got, err := c.From(r)
	if err != nil {
		return false, err
	}
	return compareDigest(got.Bytes(), target), nil
}

// Hasher 返回一个全新的标准库增量哈希对象，供与 io.MultiWriter、io.Copy、
// io.TeeReader 组合（一次读取算多个摘要）。
//
// 注意：返回对象持有增量状态，非并发安全——须每个协程各自调用 Hasher()
// 取得独立实例，不要跨协程共享；描述器 c 本身只读，可安全共享。
func (c *HashComparer) Hasher() hash.Hash { return c.newFunc() }

// ByName 返回一次性摘要函数（已发布类型 HashFunc），由构造器表派生。
func ByName(name string) (HashFunc, error) {
	f, err := newFuncByName(name)
	if err != nil {
		return nil, err
	}
	return func(msg []byte) bytex.Bytes { return sum(f, msg) }, nil
}

// newFuncByName 按名查构造器，大小写不敏感。
func newFuncByName(name string) (func() hash.Hash, error) {
	if f, ok := hashNewFuncs[strings.ToUpper(name)]; ok {
		return f, nil
	}
	return nil, fmt.Errorf("unsupported hash function %q, supported: md5, sha1, sha224, sha256, sha384, sha512, sm3", name)
}

// Deprecated: MD5 已不安全，不应用于安全场景。仅用于兼容性。
// Md5 计算消息的 MD5 摘要。
//
// 警告：MD5 已被破解（存在碰撞攻击），仅限兼容/非安全用途
// （如校验和、去重），禁止用于密码存储、签名、MAC 等安全场景。
func Md5(msg []byte) bytex.Bytes { return sum(md5.New, msg) }

// Deprecated: SHA1 已不安全，不应用于安全场景。仅用于兼容性。
// Sha1 计算消息的 SHA-1 摘要。
//
// 警告：SHA-1 已被破解（存在碰撞攻击），仅限兼容/非安全用途
// （如校验和、去重），禁止用于密码存储、签名、MAC 等安全场景。
func Sha1(msg []byte) bytex.Bytes { return sum(sha1.New, msg) }

func Sha224(msg []byte) bytex.Bytes { return sum(sha256.New224, msg) }

func Sha256(msg []byte) bytex.Bytes { return sum(sha256.New, msg) }

func Sha384(msg []byte) bytex.Bytes { return sum(sha512.New384, msg) }

func Sha512(msg []byte) bytex.Bytes { return sum(sha512.New, msg) }

func Sm3(msg []byte) bytex.Bytes { return sum(sm3.New, msg) }

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

func sum(f func() hash.Hash, msg []byte) bytex.Bytes {
	h := f()

	_, _ = h.Write(msg)
	return h.Sum(nil)
}

// sumFrom 从 r 流式读取并增量写入哈希对象，返回摘要。
// io.Copy 内部使用固定大小缓冲，数据不会一次性载入内存。
func sumFrom(f func() hash.Hash, r io.Reader) (bytex.Bytes, error) {
	h := f()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// sum64From 从 r 流式读取并增量写入 64 位哈希对象，返回整型哈希值。
func sum64From(h hash.Hash64, r io.Reader) (uint64, error) {
	if _, err := io.Copy(h, r); err != nil {
		return 0, err
	}
	return h.Sum64(), nil
}

// Md5From 从 r 流式计算 MD5 摘要，读取过程中返回错误。
//
// Deprecated: 与 Md5 相同，MD5 已不安全，仅限兼容/非安全用途。
func Md5From(r io.Reader) (bytex.Bytes, error) { return sumFrom(md5.New, r) }

// Sha1From 从 r 流式计算 SHA-1 摘要，读取过程中返回错误。
//
// Deprecated: 与 Sha1 相同，SHA-1 已不安全，仅限兼容/非安全用途。
func Sha1From(r io.Reader) (bytex.Bytes, error) { return sumFrom(sha1.New, r) }

// Sha224From 从 r 流式计算 SHA-224 摘要，读取过程中返回错误。
func Sha224From(r io.Reader) (bytex.Bytes, error) { return sumFrom(sha256.New224, r) }

// Sha256From 从 r 流式计算 SHA-256 摘要，读取过程中返回错误。
func Sha256From(r io.Reader) (bytex.Bytes, error) { return sumFrom(sha256.New, r) }

// Sha384From 从 r 流式计算 SHA-384 摘要，读取过程中返回错误。
func Sha384From(r io.Reader) (bytex.Bytes, error) { return sumFrom(sha512.New384, r) }

// Sha512From 从 r 流式计算 SHA-512 摘要，读取过程中返回错误。
func Sha512From(r io.Reader) (bytex.Bytes, error) { return sumFrom(sha512.New, r) }

// Sm3From 从 r 流式计算 SM3 摘要，读取过程中返回错误。
func Sm3From(r io.Reader) (bytex.Bytes, error) { return sumFrom(sm3.New, r) }

// Murmur3From 从 r 流式计算 Murmur3 64 位哈希，读取过程中返回错误。
//
// 注意：非加密哈希，适用场景与 Murmur3 相同。
func Murmur3From(r io.Reader) (uint64, error) { return sum64From(murmur3.New64(), r) }

// XXhashFrom 从 r 流式计算 xxhash 摘要（64 位，返回 8 字节），读取过程中返回错误。
//
// 注意：非加密哈希，适用场景与 XXhash 相同。
func XXhashFrom(r io.Reader) ([]byte, error) {
	h := xxhash.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// XXHashUint64From 从 r 流式计算 xxhash 64 位整型哈希，读取过程中返回错误。
//
// 注意：非加密哈希，适用场景与 XXHashUint64 相同。
func XXHashUint64From(r io.Reader) (uint64, error) { return sum64From(xxhash.New(), r) }

// Fnv32From 从 r 流式计算 FNV-1a 32 位哈希，读取过程中返回错误。
//
// 注意：非加密哈希，适用场景与 Fnv32 相同。
func Fnv32From(r io.Reader) (uint32, error) {
	h := fnv.New32()
	if _, err := io.Copy(h, r); err != nil {
		return 0, err
	}
	return h.Sum32(), nil
}

// Fnv64From 从 r 流式计算 FNV-1a 64 位哈希，读取过程中返回错误。
//
// 注意：非加密哈希，适用场景与 Fnv64 相同。
func Fnv64From(r io.Reader) (uint64, error) { return sum64From(fnv.New64(), r) }
