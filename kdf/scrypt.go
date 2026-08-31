package kdf

import (
	"errors"

	"golang.org/x/crypto/scrypt"
)

// ErrKDFParamsTooLarge 口令派生/校验参数超过 DoS 防护上限时返回的哨兵错误。
//
// 由 Scrypt、PasswordHash、PasswordVerify 统一返回，调用方可用 errors.Is
// 判断；错误信息不含具体数值，避免向攻击者泄露内部上限（对齐
// keymgr/pbes2.go 中解密侧迭代上限的错误处理纪律）。
var ErrKDFParamsTooLarge = errors.New("kdf: KDF parameters too large")

// scryptMaxCost 单次 scrypt 派生的成本上限：N * r * p 不得超过 2^22
// （4194304，约 419 万）。
//
// 依据：OWASP 2024 口令哈希推荐参数组合 N=2^15、r=8、p=1，其成本
// N*r*p = 2^18 = 262144；本上限为其 16 倍余量（N、r、p 各维度约 4 倍
// 余量），既覆盖硬件升级空间，又阻止恶意参数（如 p 或 N 取 2^31 级）
// 导致的 CPU/内存 DoS。
const scryptMaxCost = 1 << 22

// Scrypt 基于密码的内存硬密钥派生函数（RFC 7914）。
//
// 参数：
//   - N：CPU/内存成本参数，必须为 >1 的 2 的幂
//   - r：块大小参数（每个块 128 字节，建议 8）
//   - p：并行度参数（建议 1）
//   - password：用户密码
//   - salt：盐值（建议至少 16 字节随机值，每次派生唯一）
//   - keyLen：输出密钥长度（字节）
//
// 返回：
//   - 派生密钥（长度 keyLen）
//   - 错误（参数非法或超过 DoS 上限时，超限返回 ErrKDFParamsTooLarge）
//
// DoS 上限：N * r * p <= 2^22（约 419 万），避免恶意超大参数拖垮
// CPU/内存（压低开销的具体理由见 scryptMaxCost 注释）。
//
// OWASP 推荐参数（2024，口令哈希场景）：
//
//	N=2^15（32768）、r=8、p=1、keyLen=32
//
// 该组合在主流硬件上约 100ms 完成、内存约 32MiB。示例：
//
//	dk, _ := kdf.Scrypt(1<<15, 8, 1, []byte("password"), salt, 32)
//	// dk: 32 字节 AES-256 密钥
func Scrypt(N, r, p int, password, salt []byte, keyLen int) ([]byte, error) {
	if N <= 1 || N&(N-1) != 0 {
		return nil, errors.New("kdf: N must be > 1 and a power of 2")
	}
	if r <= 0 {
		return nil, errors.New("kdf: r must be positive")
	}
	if p <= 0 {
		return nil, errors.New("kdf: p must be positive")
	}
	if keyLen <= 0 {
		return nil, errors.New("kdf: keyLen must be positive")
	}

	// DoS 上限：N * r * p <= scryptMaxCost。
	// 采用逐级除法约束，避免中间乘积溢出（int/uint64 均不可靠时使用
	// 除法保序比较：先约束各单项与 r*p，再约束 N 与 r*p 的商）。
	if N > scryptMaxCost || r > scryptMaxCost || p > scryptMaxCost {
		return nil, ErrKDFParamsTooLarge
	}
	rp := uint64(r) * uint64(p) // r、p 均 <= 2^22，乘积 <= 2^44，无溢出
	if rp > scryptMaxCost {
		return nil, ErrKDFParamsTooLarge
	}
	if uint64(N) > scryptMaxCost/rp { // N*rp <= 2^22 * 2^22 = 2^44，无溢出
		return nil, ErrKDFParamsTooLarge
	}

	return scrypt.Key(password, salt, N, r, p, keyLen)
}
