package envelope

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	rootcrypto "github.com/charlienet/go-crypto/crypto"
)

// 分块 GCM 认证加密（格式 "fsb1"）。
//
// 明文按 ChunkSize 分块，每块使用 AES/SM4-GCM 独立加密，输出为连续的
// "密文块 || 16 字节认证标签" 流。块 nonce 由 baseNonce（12 字节）视为
// 大端 96 位整数按块号递增派生，AAD 绑定格式魔数、明文总长与块号，
// 用于防重排、截断与拼接。
const (
	ChunkSize   = 4096 // 每块明文大小
	TagSize     = 16   // GCM 认证标签长度
	FormatMagic = "fsb1"
)

// 标准库 GCM 的 nonce 大小。非 12 字节 nonce 有性能退化，显式校验。
const blockNonceSize = 12

// maxProbeStall 解密探测循环中连续 (0, nil) 读的最大次数上限，
// 防止底层 reader 持续空转导致忙等死循环。
const maxProbeStall = 128

var (
	// ErrCipherTooLong 解密时密文超出预期块数。
	ErrCipherTooLong = errors.New("block aead: ciphertext extends beyond expected block count")
	// ErrCipherTruncated 密文提前截断。
	ErrCipherTruncated = errors.New("block aead: ciphertext truncated")
	// ErrSizeMismatch 加密时实际读到的明文字节数与 totalSize 不符。
	ErrSizeMismatch = errors.New("block aead: plaintext size mismatch with totalSize")
	// ErrNonceOverflow 块号使 nonce 超出 96 位空间。
	ErrNonceOverflow = errors.New("block aead: nonce overflow")
	// ErrInvalidBaseNonce baseNonce 长度非法（必须 12 字节）。
	ErrInvalidBaseNonce = errors.New("block aead: invalid base nonce, must be 12 bytes")
	// ErrNoProgress 解密探测循环中底层 reader 持续 (0, nil) 空转、
	// 达到 maxProbeStall 上限仍无进展，判定为忙等异常。
	ErrNoProgress = errors.New("block aead: reader made no progress")
)

// deriveNonce 将 baseNonce 视为大端 96 位整数加上 blockIndex，返回 12 字节。
// 若加法导致 nonce 超过 2^96-1（回绕），返回 ErrNonceOverflow。
func deriveNonce(base []byte, blockIndex uint64) ([]byte, error) {
	if len(base) != blockNonceSize {
		return nil, ErrInvalidBaseNonce
	}

	nonce := make([]byte, blockNonceSize)
	copy(nonce, base)

	// 低 64 位 + 块号，高 32 位单独进位。
	lo := binary.BigEndian.Uint64(nonce[4:])
	hi := uint64(binary.BigEndian.Uint32(nonce[:4]))

	lo += blockIndex
	if lo < blockIndex { // 低 64 位溢出，向高 32 位进位
		hi++
	}
	if hi > 0xFFFFFFFF { // 高 32 位溢出，整个 nonce 超过 2^96-1
		return nil, ErrNonceOverflow
	}

	binary.BigEndian.PutUint64(nonce[4:], lo)
	binary.BigEndian.PutUint32(nonce[:4], uint32(hi))
	return nonce, nil
}

// buildAAD 构造块认证附加数据：
// FormatMagic(4B) || BE64(明文总长) || BE64(块号)，共 20 字节。
func buildAAD(totalSize int64, blockIndex uint64) []byte {
	aad := make([]byte, 4+8+8)
	copy(aad, FormatMagic)
	binary.BigEndian.PutUint64(aad[4:], uint64(totalSize))
	binary.BigEndian.PutUint64(aad[12:], blockIndex)
	return aad
}

// EncryptingReader 从 src 读取明文，按 ChunkSize 分块 GCM 加密，
// 输出连续的 "密文块 || 认证标签" 流。内部统计实际读到的明文字节数，
// 结束时必须等于 totalSize，否则返回 ErrSizeMismatch。
// 空文件（totalSize=0）输出空流，不报错。
//
// 非并发安全：内部维护分块与缓冲状态，每个使用方应持有独立实例。
type EncryptingReader struct {
	src       io.Reader
	aead      cipher.AEAD
	baseNonce []byte
	totalSize int64

	blockIndex uint64 // 下一块块号
	readTotal  int64  // 已读明文字节数
	buf        []byte // ChunkSize 明文缓冲
	out        []byte // 当前块密文缓冲（CT||TAG）
	err        error  // 已发生的错误（返回后固定返回该错误）
}

// Length 返回完整密文流的字节长度。
//
// 分块 GCM 输出为连续的"密文块 || 16 字节认证标签"流：明文每 ChunkSize 一块，
// 共 ceil(totalSize/ChunkSize) 块，每块附加 TagSize 字节标签。因此
// 完整密文长度 = totalSize + TagSize * ceil(totalSize/ChunkSize)；
// 空文件（totalSize=0）无任何块，长度为 0。
//
// 该长度可在读取前精确预知。EncryptingReader 仅实现 io.Reader、不可 seek，
// 不可 seek 流需预知长度（ContentLength 或显式校验和），否则上传会失败。
func (r *EncryptingReader) Length() int64 {
	if r.totalSize == 0 {
		return 0
	}
	numBlocks := (r.totalSize + ChunkSize - 1) / ChunkSize
	return r.totalSize + numBlocks*TagSize
}

// NewEncryptingReader 构造流式分块加密器。
func NewEncryptingReader(src io.Reader, c rootcrypto.Cipher, baseNonce []byte, totalSize int64) (*EncryptingReader, error) {
	if totalSize < 0 {
		return nil, fmt.Errorf("block aead: invalid totalSize %d, must be >= 0", totalSize)
	}
	// 上界校验：totalSize 过大会使 Length()/块数计算中的
	// (totalSize + ChunkSize - 1) 回绕为负，块数错乱；此处提前拒绝。
	if totalSize > math.MaxInt64-(ChunkSize-1) {
		return nil, fmt.Errorf("block aead: totalSize too large: %d", totalSize)
	}
	if len(baseNonce) != blockNonceSize {
		return nil, ErrInvalidBaseNonce
	}

	gcm, err := cipher.NewGCM(c.Block())
	if err != nil {
		return nil, err
	}

	return &EncryptingReader{
		src:       src,
		aead:      gcm,
		baseNonce: append([]byte(nil), baseNonce...),
		totalSize: totalSize,
		buf:       make([]byte, ChunkSize),
	}, nil
}

// Read 实现 io.Reader，错误在读取过程中返回，且错误返回后后续 Read
// 恒返回 (0, 相同错误)。
func (r *EncryptingReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}

	for {
		if len(r.out) > 0 {
			n := copy(p, r.out)
			r.out = r.out[n:]
			return n, nil
		}

		done, err := r.nextBlock()
		if err != nil {
			r.err = err
			return 0, err
		}
		if done {
			if r.readTotal != r.totalSize {
				r.err = ErrSizeMismatch
				return 0, r.err
			}
			r.err = io.EOF
			return 0, io.EOF
		}
	}
}

// nextBlock 从 src 读取下一块明文并加密填充 out。
// 返回 done=true 表示 src 已读完且无数据剩余。
func (r *EncryptingReader) nextBlock() (bool, error) {
	n, err := io.ReadFull(r.src, r.buf)
	switch err {
	case nil:
		// 满块
	case io.EOF:
		// n == 0，src 无剩余数据
		return true, nil
	case io.ErrUnexpectedEOF:
		// 最后一块不满
	default:
		return false, err
	}
	if n == 0 {
		return true, nil
	}

	r.readTotal += int64(n)
	nonce, err := deriveNonce(r.baseNonce, r.blockIndex)
	if err != nil {
		return false, err
	}
	aad := buildAAD(r.totalSize, r.blockIndex)
	r.out = r.aead.Seal(nil, nonce, r.buf[:n], aad)
	r.blockIndex++
	return false, nil
}

// DecryptingReader 从 src 读取密文，逐块验证 GCM 认证标签，验证通过
// 才输出明文。读完 ceil(totalSize/ChunkSize) 块后若 src 仍有剩余字节
// 返回 ErrCipherTooLong；中途 EOF 且块数不足返回 ErrCipherTruncated；
// 任一标签验证失败返回 GCM 认证错误。
//
// 非并发安全：内部维护分块与缓冲状态，每个使用方应持有独立实例。
type DecryptingReader struct {
	src       io.Reader
	aead      cipher.AEAD
	baseNonce []byte
	totalSize int64
	numBlocks uint64 // 预期块数 = ceil(totalSize/ChunkSize)

	blockIndex uint64 // 下一块块号
	out        []byte // 当前块明文缓冲
	err        error  // 已发生的错误（返回后固定返回该错误）
}

// NewDecryptingReader 构造流式分块解密器。
func NewDecryptingReader(src io.Reader, c rootcrypto.Cipher, baseNonce []byte, totalSize int64) (*DecryptingReader, error) {
	if totalSize < 0 {
		return nil, fmt.Errorf("block aead: invalid totalSize %d, must be >= 0", totalSize)
	}
	// 上界校验：与 NewEncryptingReader 同源，防止块数计算回绕为负。
	if totalSize > math.MaxInt64-(ChunkSize-1) {
		return nil, fmt.Errorf("block aead: totalSize too large: %d", totalSize)
	}
	if len(baseNonce) != blockNonceSize {
		return nil, ErrInvalidBaseNonce
	}

	gcm, err := cipher.NewGCM(c.Block())
	if err != nil {
		return nil, err
	}

	numBlocks := uint64(0)
	if totalSize > 0 {
		numBlocks = uint64((totalSize + ChunkSize - 1) / ChunkSize)
	}

	return &DecryptingReader{
		src:       src,
		aead:      gcm,
		baseNonce: append([]byte(nil), baseNonce...),
		totalSize: totalSize,
		numBlocks: numBlocks,
	}, nil
}

// Read 实现 io.Reader，错误在读取过程中返回，且错误返回后后续 Read
// 恒返回 (0, 相同错误)。
func (r *DecryptingReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}

	for {
		if len(r.out) > 0 {
			n := copy(p, r.out)
			r.out = r.out[n:]
			return n, nil
		}

		done, err := r.nextBlock()
		if err != nil {
			r.err = err
			return 0, err
		}
		if done {
			r.err = io.EOF
			return 0, io.EOF
		}
	}
}

// nextBlock 读取并验证下一块密文，验证通过填充 out。
// 返回 done=true 表示所有块均已处理且 src 无多余密文。
func (r *DecryptingReader) nextBlock() (bool, error) {
	// 所有预期块处理完毕：校验 src 是否还有多余密文。
	if r.blockIndex >= r.numBlocks {
		var probe [1]byte
		stalled := 0 // 连续 (0, nil) 空转计数（读到数据即直接返回，计数仅针对连续空转）
		for {
			n, err := r.src.Read(probe[:])
			if n > 0 {
				return false, ErrCipherTooLong
			}
			if err == io.EOF {
				return true, nil
			}
			if err != nil {
				return false, err
			}
			// n == 0 && err == nil：底层 reader 未推进。连续空转达到上限
			// 视为异常，返回 ErrNoProgress 哨兵避免无限忙等。
			stalled++
			if stalled >= maxProbeStall {
				return false, ErrNoProgress
			}
		}
	}

	// 计算本块明文长度（最后一块可能不满 ChunkSize）。
	plainLen := int64(ChunkSize)
	if r.blockIndex == r.numBlocks-1 {
		plainLen = r.totalSize - int64(r.blockIndex)*ChunkSize
	}

	cipherLen := plainLen + TagSize
	ct := make([]byte, cipherLen)
	if _, err := io.ReadFull(r.src, ct); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, ErrCipherTruncated
		}
		return false, err
	}

	nonce, err := deriveNonce(r.baseNonce, r.blockIndex)
	if err != nil {
		return false, err
	}
	aad := buildAAD(r.totalSize, r.blockIndex)

	pt, err := r.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return false, err
	}
	r.out = pt
	r.blockIndex++
	return false, nil
}
