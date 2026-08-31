package envelope

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	rootcrypto "github.com/charlienet/go-crypto"
)

// 分块 GCM 认证加密（格式 "fsb1" 与自描述 "fsb2"）。
//
// 明文按 ChunkSize 分块，每块使用 AES/SM4-GCM 独立加密，输出为连续的
// "密文块 || 16 字节认证标签" 流。块 nonce 由 baseNonce（12 字节）视为
// 大端 96 位整数按块号递增派生，AAD 绑定格式魔数、明文总长与块号，
// 用于防重排、截断与拼接。
//
// fsb1 为遗留格式：无容器头部，baseNonce/明文总长/算法带外管理，
// 已冻结只读。新集成请使用 fsb2 自描述容器（见 doc.go 与
// NewFileEncrypter / NewFileDecryptingReader）。
const (
	ChunkSize   = 4096 // 每块明文大小
	TagSize     = 16   // GCM 认证标签长度
	FormatMagic = "fsb1"
)

// fsb2 自描述文件容器头部字节布局（固定 28 字节，紧凑打包）：
//
//	offset  size  field
//	0       6     magic "GOFSB2"
//	6       1     version（0x00，首版冻结）
//	7       1     algID（查表映射 symmetric 注册键）
//	8       12    baseNonce（随机 12 字节）
//	20      8     明文总长（uint64 小端）
//
// 分块大小固定 ChunkSize（与 fsb1 一致，常量不可配置），不入头部。
// 头部整体（28 字节）作为每块 GCM AAD 前缀绑定（参照 gcx1 v2 的
// header 入 AAD 防篡改做法），块号以 BE64 追加在后。
const (
	fsb2Magic      = "GOFSB2"
	fsb2Version    = 0x00       // 版本 0：首个冻结版本
	fsb2AlgIDLen   = 1          // 算法标识字节长度
	fsb2NonceLen   = 12         // baseNonce 长度（与 blockNonceSize 一致）
	fsb2SizeLen    = 8          // 明文总长（uint64 LE）
	fsb2HeaderLen  = len(fsb2Magic) + 1 + fsb2AlgIDLen + fsb2NonceLen + fsb2SizeLen // = 28
	fsb2SizeOffset = len(fsb2Magic) + 1 + fsb2AlgIDLen + fsb2NonceLen              // totalSize 字段偏移 = 20

	// fsb2 算法标识字节（查表映射 symmetric 注册键，复用 gcx1 全局 ID 语义）。
	fsb2AlgIDSM4    byte = 0x01
	fsb2AlgIDAES128 byte = 0x02
	fsb2AlgIDAES192 byte = 0x03
	fsb2AlgIDAES256 byte = 0x04
	fsb2AlgIDDES    byte = 0x05 // 已知不安全算法：头部分发时显式拒绝
	fsb2AlgID3DES   byte = 0x06
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

	// —— fsb2 自描述容器哨兵错误 ——
	// ErrFsb2BadHeader 密文流头读取不完整/过短。
	ErrFsb2BadHeader = errors.New("fsb2: header truncated")
	// ErrFsb2MagicMismatch 头部魔数不符，非 fsb2 容器。
	ErrFsb2MagicMismatch = errors.New("fsb2: magic mismatch, not a GOFSB2 container")
	// ErrFsb2VersionMismatch 头部版本号不受支持。
	ErrFsb2VersionMismatch = errors.New("fsb2: unsupported container version")
	// ErrFsb2UnknownAlg 头部声明的算法标识未注册/不存在。
	ErrFsb2UnknownAlg = errors.New("fsb2: header declares an algorithm not in the symmetric registry")
	// ErrFsb2InsecureAlg 头部声明的算法不安全（DES/3DES）。
	ErrFsb2InsecureAlg = errors.New("fsb2: header declares an insecure algorithm (DES/3DES)")
	// ErrFsb2KeyMismatch 提交的密钥长度与头部声明算法不匹配。
	ErrFsb2KeyMismatch = errors.New("fsb2: key length does not match the algorithm declared in the header")
	// ErrFsb2BadSize 头部声明的明文总长非法（负数/上界溢出）。
	ErrFsb2BadSize = errors.New("fsb2: header declares an invalid totalSize")
)

// fsb2AlgIDByName 规范算法名（symmetric 注册键）→ fsb2 algID 字节。
var fsb2AlgIDByName = map[string]byte{
	rootcrypto.AlgorithmSM4:    fsb2AlgIDSM4,
	rootcrypto.AlgorithmAES128: fsb2AlgIDAES128,
	rootcrypto.AlgorithmAES192: fsb2AlgIDAES192,
	rootcrypto.AlgorithmAES256: fsb2AlgIDAES256,
}

// fsb2AlgNameByID fsb2 algID 字节 → 规范算法名。DES/3DES 不在此表（不安全，
// 头部校验返回 ErrFsb2InsecureAlg）。
var fsb2AlgNameByID = map[byte]string{
	fsb2AlgIDSM4:    rootcrypto.AlgorithmSM4,
	fsb2AlgIDAES128: rootcrypto.AlgorithmAES128,
	fsb2AlgIDAES192: rootcrypto.AlgorithmAES192,
	fsb2AlgIDAES256: rootcrypto.AlgorithmAES256,
}

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

// buildAAD 构造 fsb1 块认证附加数据：
// FormatMagic(4B) || BE64(明文总长) || BE64(块号)，共 20 字节。
func buildAAD(totalSize int64, blockIndex uint64) []byte {
	aad := make([]byte, 4+8+8)
	copy(aad, FormatMagic)
	binary.BigEndian.PutUint64(aad[4:], uint64(totalSize))
	binary.BigEndian.PutUint64(aad[12:], blockIndex)
	return aad
}

// buildFsb2AAD 构造 fsb2 块认证附加数据：完整头部（28 字节，含 magic/
// version/algID/baseNonce/totalSize，参照 gcx1 v2 的 header 入 AAD 做法）
// || BE64(块号)，共计 36 字节。头部整体入 AAD 使任何头部字节的篡改
// （含算法混淆）都被该块 GCM 认证拒绝；块号 BBI 保留 fsb1 的防重排绑定。
func buildFsb2AAD(header []byte, blockIndex uint64) []byte {
	aad := make([]byte, len(header)+8)
	copy(aad, header)
	binary.BigEndian.PutUint64(aad[len(header):], blockIndex)
	return aad
}

// EncryptingReader 从 src 读取明文，按 ChunkSize 分块 GCM 加密，
// 输出连续的 "密文块 || 认证标签" 流（fsb2 路径为 header || 块流）。
// 内部统计实际读到的明文字节数，结束时必须等于 totalSize，否则返回
// ErrSizeMismatch。空文件（totalSize=0）在 fsb1 输出空流、在 fsb2 输出
// 仅头部（28 字节），均不报错。
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

	// header 非 nil 时即 fsb2 自描述容器：输出 header || 分块密文流，
	// 且每块 AAD 使用完整头部。nil 维持 fsb1 旧行为（不含头部）。
	// headerPos 为已输出头部字节数（独立游标，避免消耗 header 切片——
	// nextBlock 构建 AAD 仍需要完整头部）。
	header        []byte
	headerEmitted bool
	headerPos     int
}

// Length 返回完整密文流的字节长度。
//
// 分块 GCM 输出为连续的"密文块 || 16 字节认证标签"流：明文每 ChunkSize 一块，
// 共 ceil(totalSize/ChunkSize) 块，每块附加 TagSize 字节标签。因此
// 完整密文长度 = totalSize + TagSize * ceil(totalSize/ChunkSize)；
// fsb2 路径额外附加 fsb2HeaderLen 字节头部；空文件（totalSize=0）无任何
// 块，fsb1 长度为 0、fsb2 长度即头部长度。
//
// 该长度可在读取前精确预知。EncryptingReader 仅实现 io.Reader、不可 seek，
// 不可 seek 流需预知长度（ContentLength 或显式校验和），否则上传会失败。
func (r *EncryptingReader) Length() int64 {
	prefix := int64(len(r.header))
	if r.totalSize == 0 {
		return prefix
	}
	numBlocks := (r.totalSize + ChunkSize - 1) / ChunkSize
	return prefix + r.totalSize + numBlocks*TagSize
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
		// fsb2 路径：先完整输出头部，再输出分块密文
		if r.header != nil && !r.headerEmitted {
			if r.headerPos < len(r.header) {
				n := copy(p, r.header[r.headerPos:])
				r.headerPos += n
				return n, nil
			}
			r.headerEmitted = true
		}

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
	if r.header != nil {
		// fsb2：完整头部入 AAD（header 已含 totalSize），仅追加块号
		aad = buildFsb2AAD(r.header, r.blockIndex)
	}
	r.out = r.aead.Seal(nil, nonce, r.buf[:n], aad)
	r.blockIndex++
	return false, nil
}

// DecryptingReader 从 src 读取密文，逐块验证 GCM 认证标签，验证通过
// 才输出明文。读完 ceil(totalSize/ChunkSize) 块后若 src 仍有剩余字节
// 返回 ErrCipherTooLong；中途 EOF 且块数不足返回 ErrCipherTruncated；
// 任一标签验证失败返回 GCM 认证错误。
//
// fsb2 路径（NewFileDecryptingReader）：头部从密文流自读，totalSize 与
// baseNonce 无需外部传入；header 入 AAD，头部任一字节被篡改即失败。
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

	// header 非 nil 时即 fsb2 自描述容器：头部已从 src 读入，
	// 每块 AAD 使用完整头部。nil 维持 fsb1 旧行为。
	header []byte
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
	if r.header != nil {
		// fsb2：完整头部入 AAD（头部已含 totalSize），仅追加块号。
		// 头部篡改（含算法混淆）在此被 GCM 认证拒绝。
		aad = buildFsb2AAD(r.header, r.blockIndex)
	}

	pt, err := r.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return false, err
	}
	r.out = pt
	r.blockIndex++
	return false, nil
}

// ==================== fsb2 自描述文件容器 ====================

// FileEncrypter fsb2 自描述文件容器加密器（流式）。
// NewFileEncrypter 校验算法与密钥长度并生成随机 baseNonce；
// 每次 Encrypt 返回绑定明文源与声明总长的 EncryptingReader。
// 非并发安全：同一实例应单协程使用。
type FileEncrypter struct {
	key       []byte
	algorithm string
	baseNonce []byte
	header    []byte // 头部骨架（totalSize 字段在 Encrypt 时填充）
}

// NewFileEncrypter 构造 fsb2 自描述文件加密器。
//
// algorithm 为 symmetric 注册键（"SM4"/"AES-128"/"AES-192"/"AES-256"，
// 支持泛名归一）；容器固定使用 GCM 分块认证加密。内部经 crypto/rand
// 生成随机 baseNonce 并写入头部，不再需要调用方带外管理 nonce 与算法。
// DES/3DES 等不安全算法在此即被拒绝（对齐 Lane A 的 Insecure 闸门）。
func NewFileEncrypter(key []byte, algorithm string) (*FileEncrypter, error) {
	norm, err := rootcrypto.NormalizeAlgorithm(algorithm)
	if err != nil {
		return nil, fmt.Errorf("fsb2: %w", err)
	}
	algID, ok := fsb2AlgIDByName[norm]
	if !ok {
		return nil, fmt.Errorf("fsb2: algorithm %q not supported by the fsb2 container (GCM 分块仅支持 SM4/AES-128/AES-192/AES-256)", norm)
	}
	// 经根包 NewCipher 做密钥长度严格校验（AES-128=16/192=24/256=32）；
	// DES/3DES 已在查表拦截，此层亦覆盖注册表元数据 Insecure 的纵深检查
	if _, err := rootcrypto.NewCipher(norm, key); err != nil {
		return nil, fmt.Errorf("fsb2: %w", err)
	}

	baseNonce := make([]byte, fsb2NonceLen)
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return nil, fmt.Errorf("fsb2: generate baseNonce: %w", err)
	}

	header := make([]byte, fsb2HeaderLen)
	copy(header[:len(fsb2Magic)], fsb2Magic)
	header[len(fsb2Magic)] = fsb2Version
	header[len(fsb2Magic)+1] = algID
	copy(header[len(fsb2Magic)+2:len(fsb2Magic)+2+fsb2NonceLen], baseNonce)
	// totalSize 字段（偏移 fsb2SizeOffset，uint64 LE）由 Encrypt 填充

	return &FileEncrypter{
		key:       append([]byte(nil), key...),
		algorithm: norm,
		baseNonce: baseNonce,
		header:    header,
	}, nil
}

// Encrypt 返回绑定 src 的 fsb2 流式加密器，输出 header || 分块密文流。
//
// totalSize 必须等于 src 将读出的全部明文字节数（通常来自文件 Stat），
// 以 uint64 LE 写入头部并随每块 AAD 绑定（头部整体入 AAD）；
// 实际读满与声明不一致由既有块级机制（ErrSizeMismatch）保证。
func (fe *FileEncrypter) Encrypt(src io.Reader, totalSize int64) (*EncryptingReader, error) {
	if totalSize < 0 {
		return nil, fmt.Errorf("fsb2: invalid totalSize %d, must be >= 0", totalSize)
	}
	if totalSize > math.MaxInt64-(ChunkSize-1) {
		return nil, fmt.Errorf("fsb2: totalSize too large: %d", totalSize)
	}

	header := append([]byte(nil), fe.header...)
	binary.LittleEndian.PutUint64(header[fsb2SizeOffset:], uint64(totalSize))

	c, err := rootcrypto.NewCipher(fe.algorithm, fe.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c.Block())
	if err != nil {
		return nil, err
	}

	return &EncryptingReader{
		src:       src,
		aead:      gcm,
		baseNonce: append([]byte(nil), fe.baseNonce...),
		totalSize: totalSize,
		buf:       make([]byte, ChunkSize),
		header:    header,
	}, nil
}

// NewFileDecryptingReader 从密文流自动读取 fsb2 头部（28 字节：
// magic/version/algID/baseNonce/明文总长），校验后构造流式解密器。
// 构造时不再需要外部传入 totalSize/baseNonce（评审 #2 根因修复）；
// 算法从头部读取并与提交的密钥长度匹配校验。
//
// 校验顺序：头部完整性 → magic → version → algID（未注册 / 不安全拒绝）
// → 密钥长度匹配 → totalSize 合法性。头部任一字节被篡改，凡未在上述
// 校验处显式失败者，均由每块 GCM AAD（header 入 AAD）认证拒绝。
func NewFileDecryptingReader(src io.Reader, key []byte) (*DecryptingReader, error) {
	header := make([]byte, fsb2HeaderLen)
	if _, err := io.ReadFull(src, header); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFsb2BadHeader, err)
	}

	if string(header[:len(fsb2Magic)]) != fsb2Magic {
		return nil, ErrFsb2MagicMismatch
	}
	if header[len(fsb2Magic)] != fsb2Version {
		return nil, ErrFsb2VersionMismatch
	}

	algID := header[len(fsb2Magic)+1]
	algName, ok := fsb2AlgNameByID[algID]
	if !ok {
		switch algID {
		case fsb2AlgIDDES, fsb2AlgID3DES:
			return nil, ErrFsb2InsecureAlg
		}
		return nil, ErrFsb2UnknownAlg
	}
	// 纵深防御：复核注册表 Insecure 元数据（与 Lane A 协议层策略一致），
	// 自定义引擎若被标记 Insecure 亦不放行
	if f, err := rootcrypto.CipherFactoryFor(algName); err == nil && f.Insecure {
		return nil, fmt.Errorf("%w: %s", ErrFsb2InsecureAlg, algName)
	}

	c, err := rootcrypto.NewCipher(algName, key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFsb2KeyMismatch, err)
	}
	gcm, err := cipher.NewGCM(c.Block())
	if err != nil {
		return nil, err
	}

	baseNonce := header[len(fsb2Magic)+2 : len(fsb2Magic)+2+fsb2NonceLen]
	totalSize := int64(binary.LittleEndian.Uint64(header[fsb2SizeOffset:]))
	if totalSize < 0 || totalSize > math.MaxInt64-(ChunkSize-1) {
		return nil, ErrFsb2BadSize
	}
	numBlocks := uint64(0)
	if totalSize > 0 {
		numBlocks = uint64((totalSize + ChunkSize - 1) / ChunkSize)
	}

	return &DecryptingReader{
		src:       src,
		aead:      gcm,
		baseNonce: baseNonce,
		totalSize: totalSize,
		numBlocks: numBlocks,
		header:    header,
	}, nil
}
