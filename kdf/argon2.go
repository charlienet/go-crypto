package kdf

import (
	"errors"

	"golang.org/x/crypto/argon2"
)

// Argon2id 内存硬密钥派生函数（RFC 9106）。
//
// 参数：
//   - password：用户密码
//   - salt：盐值（建议至少 16 字节随机值，每次派生唯一）
//   - time：迭代次数（建议 ≥ 3）
//   - memory：内存使用量（KB，建议 ≥ 64*1024 即 64MB）
//   - threads：并行度（建议 4）
//   - keyLen：输出密钥长度（字节）
//
// 返回：
//   - 派生密钥（长度 keyLen）
//   - 错误（参数非法时返回错误）
//
// 使用场景：
//   - 从用户密码派生加密密钥（新系统推荐）
//   - 抗 GPU/ASIC 攻击（内存硬函数）
//
// 安全建议：
//   - 新系统优先选择 Argon2id
//   - 内存使用量根据硬件性能调整，建议 ≥ 64MB
//   - Salt 必须唯一且随机
//
// 参数边界：
//   - 下界：memory 必须 ≥ 8*threads（KiB）。x/crypto 的 argon2.IDKey 在该下界被
//     违反时既不 panic 也不报错，而是静默产出无法被任何标准 Argon2 复现的非 RFC
//     密钥（initHash 用未 clamp 的原始 memory 编码 H0，实际内存却按 clamp 后分配），
//     故本函数前置拒绝。
//   - 上界：memory ≤ 1<<21 KiB（2 GiB）、keyLen ≤ 1<<20 字节（1 MiB），超出即拒绝，
//     防误用与内存 DoS。超大参数由调用方按输入信任域自行限制；本函数对 RFC 下界与
//     内存/输出上界做前置拒绝，不使用 recover。
//   - 失败一律以 error 返回，本函数永不 panic。
//
// 示例：
//
//	key, _ := kdf.Argon2id([]byte("password"), salt, 3, 64*1024, 4, 16)
//	// key: 16 字节 AES-128 密钥
func Argon2id(password, salt []byte, time, memory uint32, threads uint8, keyLen int) ([]byte, error) {
	if time == 0 {
		return nil, errors.New("kdf: time must be positive")
	}
	if memory == 0 {
		return nil, errors.New("kdf: memory must be positive")
	}
	if threads == 0 {
		return nil, errors.New("kdf: threads must be positive")
	}
	if keyLen <= 0 {
		return nil, errors.New("kdf: keyLen must be positive")
	}
	// 下界：memory 必须 ≥ 8*threads。x/crypto argon2.IDKey 在 memory < 8*threads
	// 时不 panic 也不报错，而是静默产出非 RFC 标准、无法被标准 Argon2 复现的密钥，
	// 故必须在此前置拒绝。用 uint64 计算 8*threads 防溢出。
	if uint64(memory) < uint64(8)*uint64(threads) {
		return nil, errors.New("kdf: memory must be at least 8*threads (KiB)")
	}
	// 上界：防误用与内存 DoS。memory ≤ 1<<21 KiB（2 GiB），keyLen ≤ 1<<20 字节（1 MiB）。
	if memory > 1<<21 {
		return nil, errors.New("kdf: memory exceeds 2 GiB limit")
	}
	if keyLen > 1<<20 {
		return nil, errors.New("kdf: keyLen exceeds 1 MiB limit")
	}

	return argon2.IDKey(password, salt, time, memory, threads, uint32(keyLen)), nil
}

// Argon2idDefault 使用默认参数的 Argon2id。
//
// 默认参数：
//   - time: 3
//   - memory: 64MB (64 * 1024 KB)
//   - threads: 4
//
// 适合大多数场景，如需调整参数请使用 Argon2id。
//
// 示例：
//
//	key, _ := kdf.Argon2idDefault([]byte("password"), salt, 16)
func Argon2idDefault(password, salt []byte, keyLen int) ([]byte, error) {
	return Argon2id(password, salt, 3, 64*1024, 4, keyLen)
}
