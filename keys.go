package ollamawg

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Key is a 32-byte Curve25519 key, used for WireGuard private, public and
// preshared keys. Its text form is standard base64, the same format `wg`
// uses, so keys are interchangeable with the official WireGuard tools.
type Key [32]byte

// GeneratePrivateKey returns a new, clamped Curve25519 private key.
func GeneratePrivateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return k, err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

// GeneratePresharedKey returns 32 random bytes for use as a WireGuard
// preshared key (an extra symmetric layer on top of the Noise handshake).
func GeneratePresharedKey() (Key, error) {
	var k Key
	_, err := rand.Read(k[:])
	return k, err
}

// PublicKey derives the public key for a private key.
func (k Key) PublicKey() Key {
	priv, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		// NewPrivateKey only fails on wrong length, which a Key cannot have.
		panic(err)
	}
	var pub Key
	copy(pub[:], priv.PublicKey().Bytes())
	return pub
}

// IsZero reports whether the key is all zeros (unset).
func (k Key) IsZero() bool { return k == Key{} }

// String returns the base64 form of the key.
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Hex returns the hex form used by the WireGuard UAPI.
func (k Key) Hex() string { return hex.EncodeToString(k[:]) }

// DeviceID returns a short, stable identifier for the device that owns this
// public key: the first 4 bytes of SHA-256(public key), hex encoded. Because
// it is derived from the WireGuard key, a device cannot claim another
// device's ID without that device's private key.
func (k Key) DeviceID() string {
	sum := sha256.Sum256(k[:])
	return hex.EncodeToString(sum[:4])
}

// ParseKey parses a base64 (wg-style) or 64-character hex key.
func ParseKey(s string) (Key, error) {
	var k Key
	s = strings.TrimSpace(s)
	var b []byte
	var err error
	if len(s) == 64 {
		b, err = hex.DecodeString(s)
	} else {
		b, err = base64.StdEncoding.DecodeString(s)
	}
	if err != nil {
		return k, fmt.Errorf("invalid key: %w", err)
	}
	if len(b) != 32 {
		return k, fmt.Errorf("invalid key: want 32 bytes, got %d", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// MarshalText implements encoding.TextMarshaler.
func (k Key) MarshalText() ([]byte, error) {
	if k.IsZero() {
		return []byte{}, nil
	}
	return []byte(k.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *Key) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*k = Key{}
		return nil
	}
	p, err := ParseKey(string(b))
	if err != nil {
		return err
	}
	*k = p
	return nil
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
