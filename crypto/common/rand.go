package common

import (
	"crypto/rand"
	"io"
)

// FillRandom 使用 crypto/rand 安全随机数完整填充 b。
// 语义与 io.ReadFull(rand.Reader, b) 等价：确保 b 被完全填充，
// 仅在读取不足（io.ErrUnexpectedEOF）或底层随机源失败时返回错误；
// 调用方无需关心填充的字节数，错误即表示填充不完整。
func FillRandom(b []byte) error {
	_, err := io.ReadFull(rand.Reader, b)
	return err
}
