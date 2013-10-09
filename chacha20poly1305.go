// Package chacha20poly1305 implements the ChaCha20Poly1305 AEAD construction as
// specified in draft-agl-tls-chacha20poly1305-00:
//
//     ChaCha20 is run with the given key and nonce and with the two counter
//     words set to zero.  The first 32 bytes of the 64 byte output are
//     saved to become the one-time key for Poly1305.  The remainder of the
//     output is discarded.  The first counter input word is set to one and
//     the plaintext is encrypted by XORing it with the output of
//     invocations of the ChaCha20 function as needed, incrementing the
//     first counter word for each block and overflowing into the second.
//     (In the case of the TLS, limits on the plaintext size mean that the
//     first counter word will never overflow in practice.)
//
//     The Poly1305 key is used to calculate a tag for the following input:
//     the concatenation of the number of bytes of additional data, the
//     additional data itself, the number of bytes of ciphertext and the
//     ciphertext itself.  Numbers are represented as 8-byte, little-endian
//     values.  The resulting tag is appended to the ciphertext, resulting
//     in the output of the AEAD operation.
//
// http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-00
package chacha20poly1305

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"github.com/codahale/chacha20"
	"github.com/codahale/poly1305"
	"hash"
)

type params struct {
	key []byte
}

// ErrAuthFailed is returned when the message authentication is invalid due to
// tampering.
var ErrAuthFailed = errors.New("chacha20poly1305: message authentication failed")

// NewChaCha20Poly1305 creates a new AEAD instance using the given key.
func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20.KeySize {
		return nil, chacha20.ErrInvalidKey
	}
	return &params{key: key}, nil
}

func (p *params) NonceSize() int {
	return chacha20.NonceSize
}

func (p *params) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != chacha20.NonceSize {
		panic("chacha20poly1305: invalid nonce size")
	}

	digest := ciphertext[len(ciphertext)-poly1305.Size:]
	ciphertext = ciphertext[0 : len(ciphertext)-poly1305.Size]

	c, h := p.initialize(nonce)

	calculateTag(h, ciphertext, data)

	if subtle.ConstantTimeCompare(h.Sum(nil), digest) != 1 {
		return nil, ErrAuthFailed
	}

	plaintext := make([]byte, len(ciphertext))
	c.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func (p *params) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != chacha20.NonceSize {
		panic("chacha20poly1305: invalid nonce size")
	}

	c, h := p.initialize(nonce)

	ciphertext := make([]byte, len(plaintext))
	c.XORKeyStream(ciphertext, plaintext)

	calculateTag(h, ciphertext, data)

	return append(dst, h.Sum(ciphertext)...)
}

func (p *params) Overhead() int {
	return poly1305.Size
}

func (p *params) initialize(nonce []byte) (cipher.Stream, hash.Hash) {
	c, err := chacha20.NewCipher(p.key, nonce)
	if err != nil {
		panic(err)
	}

	subkey := make([]byte, 64)
	c.XORKeyStream(subkey, subkey)

	h, err := poly1305.New(subkey[0:poly1305.KeySize])
	if err != nil {
		panic(err)
	}

	return c, h
}

func calculateTag(h hash.Hash, ciphertext, data []byte) {
	b := make([]byte, 8)

	binary.LittleEndian.PutUint64(b, uint64(len(data)))
	h.Write(b)
	h.Write(data)

	binary.LittleEndian.PutUint64(b, uint64(len(ciphertext)))
	h.Write(b)
	h.Write(ciphertext)
}
