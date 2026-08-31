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

func New(fname string, key []byte) (*HMacComparer, error) {
	f, err := ByName(fname)
	if err != nil {
		return nil, err
	}

	return &HMacComparer{
		key:      key,
		hashFunc: f,
	}, nil
}

func (c *HMacComparer) Sign(msg []byte) (bytex.Bytes, error) {
	ret := c.hashFunc(c.key, msg)
	return ret, nil
}

func (c *HMacComparer) Verify(msg, target []byte) bool {
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

	return nil, fmt.Errorf("unsupported hash function %q, supported: md5, sha1, sha224, sha256, sha384, sha512, sm3", name)
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
