package chacha20poly1305

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

const benchSize = 1024 * 1024

func benchmarkAEAD(b *testing.B, c cipher.AEAD) {
	b.SetBytes(benchSize)
	input := make([]byte, benchSize)
	output := make([]byte, benchSize)
	nonce := make([]byte, c.NonceSize())

	for i := 0; i < b.N; i++ {
		c.Seal(output[:0], nonce, input, nil)
	}
}

func BenchmarkChaCha20Poly1305(b *testing.B) {
	key := make([]byte, KeySize)
	c, _ := NewChaCha20Poly1305(key)
	benchmarkAEAD(b, c)
}

func BenchmarkAESGCM(b *testing.B) {
	key := make([]byte, 32)
	a, _ := aes.NewCipher(key)
	c, _ := cipher.NewGCM(a)
	benchmarkAEAD(b, c)
}
