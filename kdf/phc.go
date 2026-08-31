package kdf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// 口令存储（PHC 字符串）默认参数与上限。
//
// 默认参数与 keymgr 内部 Argon2id 基线（Argon2idDefault：t=3、m=64MiB、p=4）
// 一致，keyLen/saltLen 取口令哈希通用值 32/16 字节。
const (
	phcDefaultAlgorithm   = "argon2id"
	phcDefaultMemoryKiB   = 64 * 1024 // 64 MiB
	phcDefaultIterations  = 3
	phcDefaultParallelism = 4
	phcDefaultKeyLen      = 32
	phcDefaultSaltLen     = 16
)

// argon2id 派生参数上限（解析侧必须拒绝超大 m/t/p，防存储文件 DoS）。
// 采用与 keymgr/pbes2.go 相同的纪律：写侧固定强度、解析侧设上限；
// 上限为默认参数留出数倍余量（m: 16 倍、t: 5 倍、p: 4 倍），
// 超限统一返回 ErrKDFParamsTooLarge。
const (
	argon2MaxMemoryKiB   = 1 << 20 // 1 GiB
	argon2MaxIterations  = 16
	argon2MaxParallelism = 16
)

// phcMaxKeyLen / phcMaxSaltLen 解析侧接受的派生输出与盐值长度上限。
// 恶意 PHC 串可携带超长 salt/hash 段，诱使解析器分配巨大缓冲；
// 上限同时约束了派生输出（x/crypto argon2 对超长 keyLen 无内置保护）。
const (
	phcMaxKeyLen  = 1024
	phcMaxSaltLen = 1024
)

// PasswordHashOptions 口令哈希（PHC 字符串存储）的参数选项。
//
// 0 值字段使用默认值（与 keymgr 内部 Argon2id 基线一致）：
//   - Algorithm: "argon2id"
//   - MemoryKiB: 65536（64 MiB）
//   - Iterations: 3
//   - Parallelism: 4
//   - KeyLen: 32
//   - SaltLen: 16
type PasswordHashOptions struct {
	// Algorithm 口令哈希算法，当前仅支持 "argon2id"。
	Algorithm string
	// MemoryKiB Argon2id 内存使用量（KiB）。
	MemoryKiB int
	// Iterations Argon2id 迭代次数。
	Iterations int
	// Parallelism Argon2id 并行度。
	Parallelism int
	// KeyLen 派生输出密钥长度（字节）。
	KeyLen int
	// SaltLen 随机盐值长度（字节）。
	SaltLen int
}

// normalizeOptions 将 0 值字段替换为默认值并返回副本（不修改入参）。
func normalizeOptions(opts *PasswordHashOptions) *PasswordHashOptions {
	o := &PasswordHashOptions{}
	if opts != nil {
		*o = *opts
	}
	if o.Algorithm == "" {
		o.Algorithm = phcDefaultAlgorithm
	}
	if o.MemoryKiB == 0 {
		o.MemoryKiB = phcDefaultMemoryKiB
	}
	if o.Iterations == 0 {
		o.Iterations = phcDefaultIterations
	}
	if o.Parallelism == 0 {
		o.Parallelism = phcDefaultParallelism
	}
	if o.KeyLen == 0 {
		o.KeyLen = phcDefaultKeyLen
	}
	if o.SaltLen == 0 {
		o.SaltLen = phcDefaultSaltLen
	}
	return o
}

// validateOptions 校验写侧参数（正数 + 派生上限，超限返回
// ErrKDFParamsTooLarge）。调用前必须先 normalizeOptions。
func validateOptions(o *PasswordHashOptions) error {
	if o.Algorithm != phcDefaultAlgorithm {
		return errors.New("kdf: unsupported password hash algorithm: " + o.Algorithm)
	}
	if o.MemoryKiB <= 0 {
		return errors.New("kdf: memoryKiB must be positive")
	}
	if o.Iterations <= 0 {
		return errors.New("kdf: iterations must be positive")
	}
	if o.Parallelism <= 0 {
		return errors.New("kdf: parallelism must be positive")
	}
	if o.KeyLen <= 0 {
		return errors.New("kdf: keyLen must be positive")
	}
	if o.SaltLen <= 0 {
		return errors.New("kdf: saltLen must be positive")
	}
	if o.MemoryKiB > argon2MaxMemoryKiB || o.Iterations > argon2MaxIterations || o.Parallelism > argon2MaxParallelism {
		return ErrKDFParamsTooLarge
	}
	if o.KeyLen > phcMaxKeyLen {
		return errors.New("kdf: keyLen too large")
	}
	if o.SaltLen > phcMaxSaltLen {
		return errors.New("kdf: saltLen too large")
	}
	return nil
}

// PasswordHash 生成 PHC 标准格式口令哈希（口令存储一体格式）。
//
// 输出形如（base64 使用 Raw StdEncoding，无 padding，对齐 argon2 参考
// 实现与 passlib）：
//
//	$argon2id$v=19$m=65536,t=3,p=4$<b64(salt)>$<b64(hash)>
//
// Salt 由 crypto/rand 生成，每次调用随机；参数与 salt 相同时，同一口令
// 的派生结果确定，因此输出可用 PasswordVerify 无状态验证。
//
// 与 DeriveKey 的区别：DeriveKey 返回二进制密钥并要求调用方自行管理 salt；
// 本函数以自包含字符串输出，salt、参数与派生结果一体存储，适合口令登录
// 场景（见 doc.go「口令存储」章节）。
//
// 注意：口令存储场景拒绝空口令——空字符串可作为"未设置口令"的哨兵值，
// 允许存入会与真实空口令用户混淆，并引入弱凭据（可在数百毫秒内枚举）。
//
// 示例：
//
//	ph, _ := kdf.PasswordHash([]byte("user-password"), nil)
//	ok, _ := kdf.PasswordVerify(ph, []byte("user-password"))
func PasswordHash(password []byte, opts *PasswordHashOptions) (string, error) {
	if len(password) == 0 {
		return "", errors.New("kdf: password must not be empty")
	}
	o := normalizeOptions(opts)
	if err := validateOptions(o); err != nil {
		return "", err
	}

	// crypto/rand 生成随机盐（每次派生唯一，参考 argon2.go 安全建议）
	salt := make([]byte, o.SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	dk, err := Argon2id(password, salt, uint32(o.Iterations), uint32(o.MemoryKiB), uint8(o.Parallelism), o.KeyLen)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, o.MemoryKiB, o.Iterations, o.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

// phcHash 解析后的 PHC 哈希字段。
type phcHash struct {
	algorithm   string
	memoryKiB   int // argon2id 的 m
	iterations  int // argon2id 的 t
	parallelism int // argon2id 的 p
	ln          int // scrypt 的 ln（N = 2^ln）
	r           int // scrypt 的 r
	p           int // scrypt 的 p
	salt        []byte
	hash        []byte
}

// parsePHCString 严格解析 PHC 字符串：字段数、算法白名单、参数与
// 长度上限。超限参数返回 ErrKDFParamsTooLarge（拒绝超大 m/t/p 的
// 恶意存储串，防解析路径 DoS，对齐 keymgr/pbes2.go 的迭代上限纪律）。
func parsePHCString(s string) (*phcHash, error) {
	parts := strings.Split(s, "$")
	// argon2id：$alg$v=19$params$salt$hash 共 6 段；
	// scrypt：  $alg$params$salt$hash      共 5 段（无版本段）
	if len(parts) < 3 || parts[0] != "" || parts[len(parts)-1] == "" {
		return nil, errors.New("kdf: invalid PHC string")
	}
	ph := &phcHash{algorithm: parts[1]}
	var saltIdx, hashIdx int
	switch ph.algorithm {
	case "argon2id":
		if len(parts) != 6 || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
			return nil, errors.New("kdf: invalid PHC argon2id encoding")
		}
		if err := parseArgon2idParams(ph, parts[3]); err != nil {
			return nil, err
		}
		saltIdx, hashIdx = 4, 5
	case "scrypt":
		// scrypt 分支：仅验证侧保留（读取旧库 scrypt 存储串），
		// 写侧统一 argon2id（见 PasswordHash 注释）。
		if len(parts) != 5 {
			return nil, errors.New("kdf: invalid PHC scrypt encoding")
		}
		if err := parseScryptParams(ph, parts[2]); err != nil {
			return nil, err
		}
		saltIdx, hashIdx = 3, 4
	default:
		return nil, errors.New("kdf: unsupported password hash algorithm: " + ph.algorithm)
	}

	var err error
	if ph.salt, err = base64.RawStdEncoding.DecodeString(parts[saltIdx]); err != nil {
		return nil, errors.New("kdf: invalid PHC salt encoding")
	}
	if ph.hash, err = base64.RawStdEncoding.DecodeString(parts[hashIdx]); err != nil {
		return nil, errors.New("kdf: invalid PHC hash encoding")
	}
	if len(ph.salt) == 0 || len(ph.salt) > phcMaxSaltLen {
		return nil, errors.New("kdf: invalid PHC salt length")
	}
	if len(ph.hash) == 0 || len(ph.hash) > phcMaxKeyLen {
		return nil, ErrKDFParamsTooLarge
	}
	return ph, nil
}

// parseArgon2idParams 解析 "m=..,t=..,p=.." 参数段。
func parseArgon2idParams(ph *phcHash, s string) error {
	seen := make(map[string]bool, 3)
	for _, kv := range strings.Split(s, ",") {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			return errors.New("kdf: invalid PHC argon2id parameter list")
		}
		k, vs := kv[:eq], kv[eq+1:]
		if seen[k] {
			return errors.New("kdf: duplicate PHC argon2id parameter")
		}
		seen[k] = true
		v, err := strconv.Atoi(vs)
		if err != nil {
			return errors.New("kdf: invalid PHC argon2id parameter value")
		}
		switch k {
		case "m":
			ph.memoryKiB = v
		case "t":
			ph.iterations = v
		case "p":
			ph.parallelism = v
		default:
			return errors.New("kdf: unknown PHC argon2id parameter")
		}
	}
	if ph.memoryKiB <= 0 || ph.iterations <= 0 || ph.parallelism <= 0 {
		return errors.New("kdf: invalid PHC argon2id parameters")
	}
	if ph.memoryKiB > argon2MaxMemoryKiB || ph.iterations > argon2MaxIterations || ph.parallelism > argon2MaxParallelism {
		return ErrKDFParamsTooLarge
	}
	return nil
}

// parseScryptParams 解析 "ln=..,r=..,p=.." 参数段（N = 2^ln）。
// 上限复用与 Scrypt 相同的成本约束 N*r*p <= scryptMaxCost。
func parseScryptParams(ph *phcHash, s string) error {
	seen := make(map[string]bool, 3)
	for _, kv := range strings.Split(s, ",") {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			return errors.New("kdf: invalid PHC scrypt parameter list")
		}
		k, vs := kv[:eq], kv[eq+1:]
		if seen[k] {
			return errors.New("kdf: duplicate PHC scrypt parameter")
		}
		seen[k] = true
		v, err := strconv.Atoi(vs)
		if err != nil {
			return errors.New("kdf: invalid PHC scrypt parameter value")
		}
		switch k {
		case "ln":
			ph.ln = v
		case "r":
			ph.r = v
		case "p":
			ph.p = v
		default:
			return errors.New("kdf: unknown PHC scrypt parameter")
		}
	}
	if ph.ln < 1 || ph.r <= 0 || ph.p <= 0 {
		return errors.New("kdf: invalid PHC scrypt parameters")
	}
	// ln >= 63 时 N = 2^ln 超出 int 表示，必然超限，直接拒绝（防移位溢出）
	if ph.ln >= 63 {
		return ErrKDFParamsTooLarge
	}
	// 复用 Scrypt 的逐级除法约束：要求 N*r*p <= scryptMaxCost
	if ph.r > scryptMaxCost || ph.p > scryptMaxCost {
		return ErrKDFParamsTooLarge
	}
	rp := uint64(ph.r) * uint64(ph.p)
	if rp > scryptMaxCost {
		return ErrKDFParamsTooLarge
	}
	if uint64(1)<<uint(ph.ln) > scryptMaxCost/rp {
		return ErrKDFParamsTooLarge
	}
	return nil
}

// PasswordVerify 验证口令与 PHC 字符串是否匹配。
//
// 流程：严格解析并校验参数上限 → 重算派生 → crypto/subtle
// ConstantTimeCompare 常量时间比对，避免时序侧信道泄露口令信息。
// 已验证的算法：argon2id（当前写侧算法）与 scrypt（仅验证，供读取
// 旧库 scrypt 存储串；遇到合法与非法 scrypt 串分别验证或返回
// 明确错误，不会静默当作其他算法处理）。
//
// 格式非法时返回错误；格式合法但口令不匹配时返回 (false, nil)。
func PasswordVerify(phcString string, password []byte) (bool, error) {
	ph, err := parsePHCString(phcString)
	if err != nil {
		return false, err
	}

	var dk []byte
	switch ph.algorithm {
	case "argon2id":
		dk, err = Argon2id(password, ph.salt, uint32(ph.iterations), uint32(ph.memoryKiB), uint8(ph.parallelism), len(ph.hash))
	case "scrypt":
		dk, err = Scrypt(1<<uint(ph.ln), ph.r, ph.p, password, ph.salt, len(ph.hash))
	default:
		return false, errors.New("kdf: unsupported password hash algorithm: " + ph.algorithm)
	}
	if err != nil {
		return false, err
	}

	// 常量时间比较，杜绝按字节提前退出造成的时序侧信道
	return subtle.ConstantTimeCompare(dk, ph.hash) == 1, nil
}

// PasswordNeedsRehash 判断存储的 PHC 串是否需要按当前策略重新哈希。
//
// 典型用法：登录验证成功且本函数返回 true 时，用 PasswordHash 重新
// 生成并替换存储串，实现参数升级与算法迁移（密钥轮换钩子）：
//
//	ok, _ := kdf.PasswordVerify(phc, password)
//	if ok {
//	    if need, _ := kdf.PasswordNeedsRehash(phc, nil); need {
//	        newPHC, _ := kdf.PasswordHash(password, nil)
//	        // 更新存储中的 phc 为 newPHC
//	    }
//	}
//
// 判定规则：
//   - 解析串的参数（m/t/p/keyLen）与本策略不一致 → true；
//   - 解析串为非 argon2id 算法（如 scrypt）→ true（建议升级到当前算法）；
//   - 格式非法或参数超限 → 返回错误。
func PasswordNeedsRehash(phcString string, opts *PasswordHashOptions) (bool, error) {
	ph, err := parsePHCString(phcString)
	if err != nil {
		return false, err
	}
	o := normalizeOptions(opts)

	switch ph.algorithm {
	case "argon2id":
		return ph.memoryKiB != o.MemoryKiB ||
			ph.iterations != o.Iterations ||
			ph.parallelism != o.Parallelism ||
			len(ph.hash) != o.KeyLen, nil
	case "scrypt":
		// scrypt 仅保留验证，写侧已统一 argon2id：一律建议升级
		return true, nil
	default:
		return false, errors.New("kdf: unsupported password hash algorithm: " + ph.algorithm)
	}
}
