package common

import "math/big"

// ZeroBytes 将 b 逐字节清零，用于及时擦除密钥等敏感内存。
// nil 与空切片均为安全操作（无副作用）。
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroBigInt 清零大整数 z：先逐字（Word）擦除其底层内存，
// 再将其值重置为 0。nil 为安全操作（无副作用）。
func ZeroBigInt(z *big.Int) {
	if z == nil {
		return
	}
	b := z.Bits()
	for i := range b {
		b[i] = 0
	}
	z.SetInt64(0)
}
