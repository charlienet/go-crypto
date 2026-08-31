package hmac

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"
	"strings"

	"github.com/charlienet/go-crypto/common"
	"github.com/charlienet/go-utils/bytex"
	"github.com/emmansun/gmsm/sm3"
)

type HMacFunc func(key, msg []byte) bytex.Bytes

var hmacFuncs = map[string]HMacFunc{
	"HMACMD5":    Md5,
	"HMACSHA1":   Sha1,
	"HMACSHA224": Sha224,
	"HMACSHA256": Sha256,
	"HMACSHA384": Sha384,
	"HMACSHA512": Sha512,
	"HMACSM3":    Sm3,
}

type HMacComparer struct {
	key      []byte
	hashFunc HMacFunc
}

// New 构造 HMAC 比较器。key 内部拷贝保存（append([]byte(nil), key...)，
// 与 asym/ed25519.go 的注入拷贝模式一致），调用方后续修改原切片不影响
// 本实例持有的密钥副本。
func New(fname string, key []byte) (*HMacComparer, error) {
	f, err := ByName(fname)
	if err != nil {
		return nil, err
	}

	return &HMacComparer{
		key:      append([]byte(nil), key...),
		hashFunc: f,
	}, nil
}

// Zero 清零并释放持有的密钥副本（common.ZeroBytes + 置 nil），
// 用于及时擦除敏感内存。清零后本实例不可再用于验证（Verify 恒返回
// false），Sign 以 nil key 调用不会 panic 但产出无密钥意义的 HMAC，
// 调用方须避免复用已 Zero 的实例。
func (c *HMacComparer) Zero() {
	common.ZeroBytes(c.key)
	c.key = nil
}

func (c *HMacComparer) Sign(msg []byte) (bytex.Bytes, error) {
	ret := c.hashFunc(c.key, msg)
	return ret, nil
}

func (c *HMacComparer) Verify(msg, target []byte) bool {
	// Zero 后 key 为 nil：直接失败，避免以空密钥算出 HMAC 产生
	// "验证通过"的假象（亦无 panic 风险）。
	if c.key == nil {
		return false
	}

	ret := c.hashFunc(c.key, msg)

	// 长度不等直接返回 false，避免进入常量时间比较
	if len(target) != len(ret.Bytes()) {
		return false
	}

	// 使用常量时间比较，避免通过比较时间逐字节猜测摘要
	return subtle.ConstantTimeCompare(ret.Bytes(), target) == 1
}

func ByName(name string) (HMacFunc, error) {
	if f, ok := hmacFuncs[strings.ToUpper(name)]; ok {
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
