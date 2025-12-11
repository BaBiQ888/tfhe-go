package tfhe

/*
#cgo CFLAGS: -I${SRCDIR}/../../tfhe-c/release
#cgo LDFLAGS: -L${SRCDIR}/../../tfhe-c/release -ltfhe -lm -ldl -lpthread -Wl,-rpath,${SRCDIR}/../../tfhe-c/release
#include "tfhe.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// ClientKey wraps a BooleanClientKey pointer from the C API.
// Close must be called to release the underlying memory.
type ClientKey struct {
	ptr *C.struct_BooleanClientKey
}

// ServerKey wraps a BooleanServerKey pointer from the C API.
type ServerKey struct {
	ptr *C.struct_BooleanServerKey
}

// Ciphertext wraps a BooleanCiphertext pointer from the C API.
type Ciphertext struct {
	ptr *C.struct_BooleanCiphertext
}

// Uint8ClientKey wraps the generic ClientKey for integer operations.
type Uint8ClientKey struct {
	ptr *C.struct_ClientKey
}

// Uint8ServerKey wraps the generic ServerKey for integer operations.
type Uint8ServerKey struct {
	ptr *C.struct_ServerKey
}

// Uint8PublicKey wraps the PublicKey for integer operations.
type Uint8PublicKey struct {
	ptr *C.struct_PublicKey
}

// Uint8Ciphertext wraps FheUint8 pointer from the C API.
type Uint8Ciphertext struct {
	ptr *C.struct_FheUint8
}

// withServerKey pins the current goroutine to an OS thread, sets the server key
// for that thread, runs fn, then unsets and unlocks. This avoids the panic
// "server key was not properly initialized" when Go reschedules goroutines.
func withServerKey(sk *Uint8ServerKey, fn func() error) error {
	if sk == nil || sk.ptr == nil {
		return errors.New("server key is nil")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := check(C.set_server_key(sk.ptr), "set server key"); err != nil {
		return err
	}
	defer C.unset_server_key()

	return fn()
}

// check converts non-zero TFHE return codes into Go errors.
func check(code C.int, context string) error {
	if code != 0 {
		return fmt.Errorf("%s: tfhe error code %d", context, int(code))
	}
	return nil
}

// GenerateBooleanKeys produces a client/server keypair using default TFHE parameters.
func GenerateBooleanKeys() (*ClientKey, *ServerKey, error) {
	var ck *C.struct_BooleanClientKey
	var sk *C.struct_BooleanServerKey

	if err := check(C.boolean_gen_keys_with_default_parameters(&ck, &sk), "generate boolean keys"); err != nil {
		return nil, nil, err
	}

	client := &ClientKey{ptr: ck}
	server := &ServerKey{ptr: sk}

	runtime.SetFinalizer(client, func(c *ClientKey) { _ = c.Close() })
	runtime.SetFinalizer(server, func(s *ServerKey) { _ = s.Close() })

	return client, server, nil
}

// Close releases the underlying BooleanClientKey.
func (c *ClientKey) Close() error {
	if c == nil || c.ptr == nil {
		return nil
	}
	if err := check(C.boolean_destroy_client_key(c.ptr), "destroy client key"); err != nil {
		return err
	}
	c.ptr = nil
	return nil
}

// Close releases the underlying BooleanServerKey.
func (s *ServerKey) Close() error {
	if s == nil || s.ptr == nil {
		return nil
	}
	if err := check(C.boolean_destroy_server_key(s.ptr), "destroy server key"); err != nil {
		return err
	}
	s.ptr = nil
	return nil
}

// Close releases the underlying BooleanCiphertext.
func (c *Ciphertext) Close() error {
	if c == nil || c.ptr == nil {
		return nil
	}
	if err := check(C.boolean_destroy_ciphertext(c.ptr), "destroy ciphertext"); err != nil {
		return err
	}
	c.ptr = nil
	return nil
}

// EncryptBool encrypts a boolean using the provided client key.
func EncryptBool(client *ClientKey, value bool) (*Ciphertext, error) {
	if client == nil || client.ptr == nil {
		return nil, errors.New("client key is nil")
	}
	var ct *C.struct_BooleanCiphertext
	if err := check(C.boolean_client_key_encrypt(client.ptr, C.bool(value), &ct), "encrypt bool"); err != nil {
		return nil, err
	}
	cipher := &Ciphertext{ptr: ct}
	runtime.SetFinalizer(cipher, func(c *Ciphertext) { _ = c.Close() })
	return cipher, nil
}

// DecryptBool decrypts a ciphertext with the provided client key.
func DecryptBool(client *ClientKey, ct *Ciphertext) (bool, error) {
	if client == nil || client.ptr == nil {
		return false, errors.New("client key is nil")
	}
	if ct == nil || ct.ptr == nil {
		return false, errors.New("ciphertext is nil")
	}
	var result C.bool
	if err := check(C.boolean_client_key_decrypt(client.ptr, ct.ptr, &result), "decrypt bool"); err != nil {
		return false, err
	}
	return bool(result), nil
}

// And performs a homomorphic AND on two ciphertexts.
func (s *ServerKey) And(lhs, rhs *Ciphertext) (*Ciphertext, error) {
	if s == nil || s.ptr == nil {
		return nil, errors.New("server key is nil")
	}
	if lhs == nil || lhs.ptr == nil || rhs == nil || rhs.ptr == nil {
		return nil, errors.New("ciphertext is nil")
	}
	var out *C.struct_BooleanCiphertext
	if err := check(C.boolean_server_key_and(s.ptr, lhs.ptr, rhs.ptr, &out), "boolean AND"); err != nil {
		return nil, err
	}
	ct := &Ciphertext{ptr: out}
	runtime.SetFinalizer(ct, func(c *Ciphertext) { _ = c.Close() })
	return ct, nil
}

// Or performs a homomorphic OR on two ciphertexts.
func (s *ServerKey) Or(lhs, rhs *Ciphertext) (*Ciphertext, error) {
	if s == nil || s.ptr == nil {
		return nil, errors.New("server key is nil")
	}
	if lhs == nil || lhs.ptr == nil || rhs == nil || rhs.ptr == nil {
		return nil, errors.New("ciphertext is nil")
	}
	var out *C.struct_BooleanCiphertext
	if err := check(C.boolean_server_key_or(s.ptr, lhs.ptr, rhs.ptr, &out), "boolean OR"); err != nil {
		return nil, err
	}
	ct := &Ciphertext{ptr: out}
	runtime.SetFinalizer(ct, func(c *Ciphertext) { _ = c.Close() })
	return ct, nil
}

// Xor performs a homomorphic XOR on two ciphertexts.
func (s *ServerKey) Xor(lhs, rhs *Ciphertext) (*Ciphertext, error) {
	if s == nil || s.ptr == nil {
		return nil, errors.New("server key is nil")
	}
	if lhs == nil || lhs.ptr == nil || rhs == nil || rhs.ptr == nil {
		return nil, errors.New("ciphertext is nil")
	}
	var out *C.struct_BooleanCiphertext
	if err := check(C.boolean_server_key_xor(s.ptr, lhs.ptr, rhs.ptr, &out), "boolean XOR"); err != nil {
		return nil, err
	}
	ct := &Ciphertext{ptr: out}
	runtime.SetFinalizer(ct, func(c *Ciphertext) { _ = c.Close() })
	return ct, nil
}

// Not performs a homomorphic NOT on a ciphertext.
func (s *ServerKey) Not(input *Ciphertext) (*Ciphertext, error) {
	if s == nil || s.ptr == nil {
		return nil, errors.New("server key is nil")
	}
	if input == nil || input.ptr == nil {
		return nil, errors.New("ciphertext is nil")
	}
	var out *C.struct_BooleanCiphertext
	if err := check(C.boolean_server_key_not(s.ptr, input.ptr, &out), "boolean NOT"); err != nil {
		return nil, err
	}
	ct := &Ciphertext{ptr: out}
	runtime.SetFinalizer(ct, func(c *Ciphertext) { _ = c.Close() })
	return ct, nil
}

// Serialize returns a copy of the ciphertext bytes and frees the C buffer.
func (c *Ciphertext) Serialize() ([]byte, error) {
	if c == nil || c.ptr == nil {
		return nil, errors.New("ciphertext is nil")
	}
	var buf C.struct_DynamicBuffer
	if err := check(C.boolean_serialize_ciphertext(c.ptr, &buf), "serialize ciphertext"); err != nil {
		return nil, err
	}
	defer C.destroy_dynamic_buffer(&buf)

	length := int(buf.length)
	if length == 0 {
		return []byte{}, nil
	}
	data := C.GoBytes(unsafe.Pointer(buf.pointer), C.int(length))
	return data, nil
}

// DeserializeCiphertext reconstructs a ciphertext from serialized bytes.
func DeserializeCiphertext(data []byte) (*Ciphertext, error) {
	if len(data) == 0 {
		return nil, errors.New("ciphertext data is empty")
	}
	view := C.struct_DynamicBufferView{
		pointer: (*C.uchar)(unsafe.Pointer(&data[0])),
		length:  C.size_t(len(data)),
	}
	var ct *C.struct_BooleanCiphertext
	if err := check(C.boolean_deserialize_ciphertext(view, &ct), "deserialize ciphertext"); err != nil {
		return nil, err
	}
	out := &Ciphertext{ptr: ct}
	runtime.SetFinalizer(out, func(c *Ciphertext) { _ = c.Close() })
	runtime.KeepAlive(data)
	return out, nil
}

// GenerateUint8Keys builds default config and returns client/server keys set for computations.
func GenerateUint8Keys() (*Uint8ClientKey, *Uint8ServerKey, error) {
	var builder *C.struct_ConfigBuilder
	if err := check(C.config_builder_default(&builder), "config builder default"); err != nil {
		return nil, nil, err
	}

	var config *C.struct_Config
	if err := check(C.config_builder_build(builder, &config), "config builder build"); err != nil {
		return nil, nil, err
	}

	var ck *C.struct_ClientKey
	var sk *C.struct_ServerKey
	if err := check(C.generate_keys(config, &ck, &sk), "generate keys"); err != nil {
		return nil, nil, err
	}

	// Set server key for subsequent FHE ops.
	if err := check(C.set_server_key(sk), "set server key"); err != nil {
		return nil, nil, err
	}

	client := &Uint8ClientKey{ptr: ck}
	server := &Uint8ServerKey{ptr: sk}
	setServerKeyHolder(server)
	runtime.SetFinalizer(client, func(c *Uint8ClientKey) { _ = c.Close() })
	runtime.SetFinalizer(server, func(s *Uint8ServerKey) { _ = s.Close() })
	return client, server, nil
}

// Close releases the underlying ClientKey.
func (c *Uint8ClientKey) Close() error {
	if c == nil || c.ptr == nil {
		return nil
	}
	if err := check(C.client_key_destroy(c.ptr), "destroy client key"); err != nil {
		return err
	}
	c.ptr = nil
	return nil
}

// Close releases the underlying ServerKey and unsets thread-local server key if set.
func (s *Uint8ServerKey) Close() error {
	if s == nil || s.ptr == nil {
		return nil
	}
	// Unset to drop thread-local reference count; ignore errors on unset.
	_ = check(C.unset_server_key(), "unset server key")
	if err := check(C.server_key_destroy(s.ptr), "destroy server key"); err != nil {
		return err
	}
	s.ptr = nil
	return nil
}

// NewUint8PublicKey derives a PublicKey from a client key.
func NewUint8PublicKey(client *Uint8ClientKey) (*Uint8PublicKey, error) {
	if client == nil || client.ptr == nil {
		return nil, errors.New("client key is nil")
	}
	var pk *C.struct_PublicKey
	if err := check(C.public_key_new(client.ptr, &pk), "new public key"); err != nil {
		return nil, err
	}
	pub := &Uint8PublicKey{ptr: pk}
	runtime.SetFinalizer(pub, func(p *Uint8PublicKey) { _ = p.Close() })
	return pub, nil
}

// Close releases the underlying PublicKey.
func (p *Uint8PublicKey) Close() error {
	if p == nil || p.ptr == nil {
		return nil
	}
	if err := check(C.public_key_destroy(p.ptr), "destroy public key"); err != nil {
		return err
	}
	p.ptr = nil
	return nil
}

// EncryptUint8 encrypts a uint8 with the client key.
func EncryptUint8(client *Uint8ClientKey, value uint8) (*Uint8Ciphertext, error) {
	if client == nil || client.ptr == nil {
		return nil, errors.New("client key is nil")
	}
	var ct *C.struct_FheUint8
	if err := check(C.fhe_uint8_try_encrypt_with_client_key_u8(C.uchar(value), client.ptr, &ct), "encrypt uint8"); err != nil {
		return nil, err
	}
	out := &Uint8Ciphertext{ptr: ct}
	runtime.SetFinalizer(out, func(c *Uint8Ciphertext) { _ = c.Close() })
	return out, nil
}

// EncryptUint8Public encrypts a uint8 with the public key.
func EncryptUint8Public(pub *Uint8PublicKey, value uint8) (*Uint8Ciphertext, error) {
	if pub == nil || pub.ptr == nil {
		return nil, errors.New("public key is nil")
	}
	var ct *C.struct_FheUint8
	if err := check(C.fhe_uint8_try_encrypt_with_public_key_u8(C.uchar(value), pub.ptr, &ct), "encrypt uint8 with public key"); err != nil {
		return nil, err
	}
	out := &Uint8Ciphertext{ptr: ct}
	runtime.SetFinalizer(out, func(c *Uint8Ciphertext) { _ = c.Close() })
	return out, nil
}

// DecryptUint8 decrypts a uint8 ciphertext with the client key.
func DecryptUint8(client *Uint8ClientKey, ct *Uint8Ciphertext) (uint8, error) {
	if client == nil || client.ptr == nil {
		return 0, errors.New("client key is nil")
	}
	if ct == nil || ct.ptr == nil {
		return 0, errors.New("ciphertext is nil")
	}
	var result C.uchar
	if err := check(C.fhe_uint8_decrypt(ct.ptr, client.ptr, &result), "decrypt uint8"); err != nil {
		return 0, err
	}
	return uint8(result), nil
}

// Close releases the underlying FheUint8 ciphertext.
func (c *Uint8Ciphertext) Close() error {
	if c == nil || c.ptr == nil {
		return nil
	}
	if err := check(C.fhe_uint8_destroy(c.ptr), "destroy uint8 ciphertext"); err != nil {
		return err
	}
	c.ptr = nil
	return nil
}

// Uint8Add performs homomorphic addition (requires server key to be set).
func Uint8Add(lhs, rhs *Uint8Ciphertext) (*Uint8Ciphertext, error) {
	if lhs == nil || lhs.ptr == nil || rhs == nil || rhs.ptr == nil {
		return nil, errors.New("ciphertext is nil")
	}
	var out *C.struct_FheUint8
	if err := withServerKey(defaultUint8ServerKey(), func() error {
		return check(C.fhe_uint8_add(lhs.ptr, rhs.ptr, &out), "uint8 add")
	}); err != nil {
		return nil, err
	}
	ct := &Uint8Ciphertext{ptr: out}
	runtime.SetFinalizer(ct, func(c *Uint8Ciphertext) { _ = c.Close() })
	return ct, nil
}

// Uint8BitAnd performs homomorphic bitwise AND.
func Uint8BitAnd(lhs, rhs *Uint8Ciphertext) (*Uint8Ciphertext, error) {
	if lhs == nil || lhs.ptr == nil || rhs == nil || rhs.ptr == nil {
		return nil, errors.New("ciphertext is nil")
	}
	var out *C.struct_FheUint8
	if err := withServerKey(defaultUint8ServerKey(), func() error {
		return check(C.fhe_uint8_bitand(lhs.ptr, rhs.ptr, &out), "uint8 bitand")
	}); err != nil {
		return nil, err
	}
	ct := &Uint8Ciphertext{ptr: out}
	runtime.SetFinalizer(ct, func(c *Uint8Ciphertext) { _ = c.Close() })
	return ct, nil
}

// Uint8BitXor performs homomorphic bitwise XOR.
func Uint8BitXor(lhs, rhs *Uint8Ciphertext) (*Uint8Ciphertext, error) {
	if lhs == nil || lhs.ptr == nil || rhs == nil || rhs.ptr == nil {
		return nil, errors.New("ciphertext is nil")
	}
	var out *C.struct_FheUint8
	if err := withServerKey(defaultUint8ServerKey(), func() error {
		return check(C.fhe_uint8_bitxor(lhs.ptr, rhs.ptr, &out), "uint8 bitxor")
	}); err != nil {
		return nil, err
	}
	ct := &Uint8Ciphertext{ptr: out}
	runtime.SetFinalizer(ct, func(c *Uint8Ciphertext) { _ = c.Close() })
	return ct, nil
}

// defaultUint8ServerKey holds the current service server key set at init.
// It must be initialized by GenerateUint8Keys via setServerKeyHolder.
var defaultUint8ServerKeyHolder *Uint8ServerKey

func setServerKeyHolder(sk *Uint8ServerKey) {
	defaultUint8ServerKeyHolder = sk
}

func defaultUint8ServerKey() *Uint8ServerKey {
	return defaultUint8ServerKeyHolder
}

// Uint8Serialize serializes ciphertext and frees C buffer.
func (c *Uint8Ciphertext) Uint8Serialize() ([]byte, error) {
	if c == nil || c.ptr == nil {
		return nil, errors.New("ciphertext is nil")
	}
	var buf C.struct_DynamicBuffer
	if err := check(C.fhe_uint8_serialize(c.ptr, &buf), "serialize uint8 ciphertext"); err != nil {
		return nil, err
	}
	defer C.destroy_dynamic_buffer(&buf)

	length := int(buf.length)
	if length == 0 {
		return []byte{}, nil
	}
	data := C.GoBytes(unsafe.Pointer(buf.pointer), C.int(length))
	return data, nil
}

// Uint8Deserialize reconstructs a Uint8 ciphertext from bytes.
func Uint8Deserialize(data []byte) (*Uint8Ciphertext, error) {
	if len(data) == 0 {
		return nil, errors.New("ciphertext data is empty")
	}
	view := C.struct_DynamicBufferView{
		pointer: (*C.uchar)(unsafe.Pointer(&data[0])),
		length:  C.size_t(len(data)),
	}
	var ct *C.struct_FheUint8
	if err := check(C.fhe_uint8_deserialize(view, &ct), "deserialize uint8 ciphertext"); err != nil {
		return nil, err
	}
	out := &Uint8Ciphertext{ptr: ct}
	runtime.SetFinalizer(out, func(c *Uint8Ciphertext) { _ = c.Close() })
	runtime.KeepAlive(data)
	return out, nil
}
