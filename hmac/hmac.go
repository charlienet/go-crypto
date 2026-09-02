package hmac

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/charlienet/go-crypto/common"
	"github.com/charlienet/go-utils/bytex"
	"github.com/emmansun/gmsm/sm3"
)

type HMacFunc func(key, msg []byte) bytex.Bytes

// hmacNewFuncs 是唯一的算法注册表：算法名 → HMAC 底层哈希构造函数。
// 一次性版本（HMacFunc）、描述器与增量对象均由它派生，新增算法只需注册一处。
var hmacNewFuncs = map[string]func() hash.Hash{
	"HMACMD5":    md5.New,
	"HMACSHA1":   sha1.New,
	"HMACSHA224": sha256.New224,
	"HMACSHA256": sha256.New,
	"HMACSHA384": sha512.New384,
	"HMACSHA512": sha512.New,
	"HMACSM3":    sm3.New,
}

// HMacComparer 是持有密钥的 HMAC 描述器：无状态计算（Digest/Compare/From/
// CompareFrom/Hasher 均不改变实例状态），但内部持有密钥副本，勿与 Zero() 并发使用。
type HMacComparer struct {
	key     []byte
	newFunc func() hash.Hash
}

// New 构造 HMAC 比较器。key 内部拷贝保存（append([]byte(nil), key...)，
// 与 asym/ed25519.go 的注入拷贝模式一致），调用方后续修改原切片不影响
// 本实例持有的密钥副本。
func New(fname string, key []byte) (*HMacComparer, error) {
	f, err := newFuncByName(fname)
	if err != nil {
		return nil, err
	}

	return &HMacComparer{
		newFunc: f,
		key:     append([]byte(nil), key...),
	}, nil
}

// Zero 清零并释放持有的密钥副本（common.ZeroBytes + 置 nil），
// 用于及时擦除敏感内存。清零后本实例不可再用于计算，调用方须避免
// 复用已 Zero 的实例。
//
// Zero 后：Digest/From/CompareFrom 返回 ErrZeroed，Hasher panic，Compare 恒为 false。
func (c *HMacComparer) Zero() {
	common.ZeroBytes(c.key)
	c.key = nil
}

// ErrZeroed 哨兵错误：实例已 Zero() 后密钥不可用。
var ErrZeroed = errors.New("hmac: comparer has been zeroed")

// Digest 计算 msg 的 HMAC。key 已在构造时拷贝，调用方可立即清零原 key。
// 与 hash 包 Digest 不同，本方法可能失败：实例 Zero() 后密钥不可用，
// 返回 ErrZeroed 而不是静默产出无密钥意义的 MAC。
//
// 注意：与标准库 hash.Hash.Sum(b []byte) 的「追加当前摘要」语义无关。
func (c *HMacComparer) Digest(msg []byte) (bytex.Bytes, error) {
	if c.key == nil {
		return nil, ErrZeroed
	}
	return sum(c.newFunc, c.key, msg), nil
}

// Compare 计算 msg 的 MAC 并与 mac 做常量时间比较；实例已 Zero() 时恒返回 false。
func (c *HMacComparer) Compare(msg, mac []byte) bool {
	// Zero 后 key 为 nil：直接失败，避免以空密钥算出 HMAC 产生
	// "验证通过"的假象（亦无 panic 风险）。
	if c.key == nil {
		return false
	}

	ret := sum(c.newFunc, c.key, msg)
	return compareDigest(ret.Bytes(), mac)
}

// From 从 r 流式计算 HMAC，读取错误原样返回；实例已 Zero() 时返回 ErrZeroed。
func (c *HMacComparer) From(r io.Reader) (bytex.Bytes, error) {
	if c.key == nil {
		return nil, ErrZeroed
	}
	return sumFrom(c.newFunc, c.key, r)
}

// CompareFrom 从 r 流式计算 HMAC 并与 mac 做常量时间比较，适用于大文件、
// 网络流等不宜一次性读入内存的报文认证场景。
//
// 语义要点：
//   - 读取失败返回 (false, err)，布尔值不携带任何认证信息，调用方必须先判 err，
//     否则一次 IO 故障会被误读为「MAC 校验不通过」；
//   - 实例已 Zero() 时返回 (false, ErrZeroed)——绝不退化为「以空密钥比较」，
//     那会产生看似通过实则无意义的认证结果；
//   - 描述器可多协程并发调用，但勿与 Zero() 并发。
func (c *HMacComparer) CompareFrom(r io.Reader, mac []byte) (bool, error) {
	if c.key == nil {
		return false, ErrZeroed
	}
	got, err := c.From(r)
	if err != nil {
		return false, err
	}
	return compareDigest(got.Bytes(), mac), nil
}

// Hasher 返回全新的标准库增量 MAC 对象，供与 io.MultiWriter、io.Copy、
// io.TeeReader 组合（一次读取同时算摘要与 MAC）。
//
// 安全提示：标准库在构造时即把 key 派生进 ipad/opad，返回对象的内部状态
// 与密钥等价，须与密钥同等保护，不得序列化或外泄。
//
// 注意：返回对象非并发安全，须每协程各自调用；已 Zero() 的实例调用本方法
// panic——复用已销毁实例属编程错误，响铃优于静默产出无密钥 MAC。
func (c *HMacComparer) Hasher() hash.Hash {
	if c.key == nil {
		panic("hmac: Hasher called on a zeroed comparer")
	}
	return hmac.New(c.newFunc, c.key)
}

// ByName 返回一次性 MAC 函数（已发布类型 HMacFunc），由构造器表派生。
func ByName(name string) (HMacFunc, error) {
	f, err := newFuncByName(name)
	if err != nil {
		return nil, err
	}
	return func(key, msg []byte) bytex.Bytes { return sum(f, key, msg) }, nil
}

// newFuncByName 按名查构造器，大小写不敏感。
func newFuncByName(name string) (func() hash.Hash, error) {
	if f, ok := hmacNewFuncs[strings.ToUpper(name)]; ok {
		return f, nil
	}

	return nil, fmt.Errorf("unsupported HMAC function %q, supported: md5, sha1, sha224, sha256, sha384, sha512, sm3", name)
}

// Deprecated: HMAC-MD5 虽然仍安全，但建议迁移到更现代的算法。
// Md5 计算 HMAC-MD5 消息认证码。
//
// 注意：HMAC 的安全性不依赖底层哈希的碰撞抗性（即使 MD5 已被碰撞破解，
// HMAC-MD5 在标准假设下仍具伪随机性），但仅限兼容/非对抗场景，
// 新代码优先使用 HMACSHA256 或 HMACSM3。
func Md5(key, msg []byte) bytex.Bytes { return sum(md5.New, key, msg) }

// Deprecated: HMAC-SHA1 虽然仍安全，但建议迁移到更现代的算法。
// Sha1 计算 HMAC-SHA1 消息认证码。
//
// 注意：HMAC 的安全性不依赖底层哈希的碰撞抗性（即使 SHA-1 已被碰撞破解，
// HMAC-SHA1 在标准假设下仍具伪随机性），但仅限兼容/非对抗场景，
// 新代码优先使用 HMACSHA256 或 HMACSM3。
func Sha1(key, msg []byte) bytex.Bytes { return sum(sha1.New, key, msg) }

func Sha224(key, msg []byte) bytex.Bytes { return sum(sha256.New224, key, msg) }

func Sha256(key, msg []byte) bytex.Bytes { return sum(sha256.New, key, msg) }

func Sha384(key, msg []byte) bytex.Bytes { return sum(sha512.New384, key, msg) }

func Sha512(key, msg []byte) bytex.Bytes { return sum(sha512.New, key, msg) }

func Sm3(key, msg []byte) bytex.Bytes { return sum(sm3.New, key, msg) }

func sum(f func() hash.Hash, key, msg []byte) bytex.Bytes {
	h := hmac.New(f, key)

	h.Write(msg)
	return h.Sum(nil)
}

// sumFrom 从 r 流式读取并增量写入 HMAC 对象，返回消息认证码。
// io.Copy 内部使用固定大小缓冲，数据不会一次性载入内存。
func sumFrom(f func() hash.Hash, key []byte, r io.Reader) (bytex.Bytes, error) {
	h := hmac.New(f, key)
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// compareDigest 对「已算好的 MAC」与 target 做安全比较：先长度预检，
// 再常量时间比较。MAC 长度由算法固定，长度信息不泄露机密，提前返回安全。
func compareDigest(got, target []byte) bool {
	if len(target) != len(got) {
		return false
	}
	return subtle.ConstantTimeCompare(got, target) == 1
}

// Md5From 从 r 流式计算 HMAC-MD5 消息认证码，读取过程中返回错误。
//
// Deprecated: 与 Md5 相同，建议迁移到更现代的算法（如 Sha256From）。
func Md5From(key []byte, r io.Reader) (bytex.Bytes, error) { return sumFrom(md5.New, key, r) }

// Sha1From 从 r 流式计算 HMAC-SHA1 消息认证码，读取过程中返回错误。
//
// Deprecated: 与 Sha1 相同，建议迁移到更现代的算法（如 Sha256From）。
func Sha1From(key []byte, r io.Reader) (bytex.Bytes, error) { return sumFrom(sha1.New, key, r) }

// Sha224From 从 r 流式计算 HMAC-SHA224 消息认证码，读取过程中返回错误。
func Sha224From(key []byte, r io.Reader) (bytex.Bytes, error) {
	return sumFrom(sha256.New224, key, r)
}

// Sha256From 从 r 流式计算 HMAC-SHA256 消息认证码，读取过程中返回错误。
func Sha256From(key []byte, r io.Reader) (bytex.Bytes, error) { return sumFrom(sha256.New, key, r) }

// Sha384From 从 r 流式计算 HMAC-SHA384 消息认证码，读取过程中返回错误。
func Sha384From(key []byte, r io.Reader) (bytex.Bytes, error) {
	return sumFrom(sha512.New384, key, r)
}

// Sha512From 从 r 流式计算 HMAC-SHA512 消息认证码，读取过程中返回错误。
func Sha512From(key []byte, r io.Reader) (bytex.Bytes, error) { return sumFrom(sha512.New, key, r) }

// Sm3From 从 r 流式计算 HMAC-SM3 消息认证码，读取过程中返回错误。
func Sm3From(key []byte, r io.Reader) (bytex.Bytes, error) { return sumFrom(sm3.New, key, r) }
