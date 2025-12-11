package tfhe

import (
	"encoding/base64"
	"errors"
)

// BooleanService exposes high-level helpers around the low-level bindings.
type BooleanService struct {
	client *ClientKey
	server *ServerKey
}

// Uint8Service exposes helpers for 8-bit unsigned integers.
type Uint8Service struct {
	client *Uint8ClientKey
	server *Uint8ServerKey
	public *Uint8PublicKey
}

// NewBooleanService generates a fresh keypair and returns a ready-to-use service.
func NewBooleanService() (*BooleanService, error) {
	ck, sk, err := GenerateBooleanKeys()
	if err != nil {
		return nil, err
	}
	return &BooleanService{
		client: ck,
		server: sk,
	}, nil
}

// EncryptBoolToBase64 encrypts a boolean and returns a base64 ciphertext.
func (s *BooleanService) EncryptBoolToBase64(value bool) (string, error) {
	ct, err := EncryptBool(s.client, value)
	if err != nil {
		return "", err
	}
	defer ct.Close()

	bytes, err := ct.Serialize()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// DecryptBoolFromBase64 decrypts a base64 ciphertext back to bool.
func (s *BooleanService) DecryptBoolFromBase64(ctBase64 string) (bool, error) {
	ct, err := deserialize(ctBase64)
	if err != nil {
		return false, err
	}
	defer ct.Close()
	return DecryptBool(s.client, ct)
}

// AndBase64 performs homomorphic AND on two base64 ciphertexts.
func (s *BooleanService) AndBase64(lhs, rhs string) (string, error) {
	return s.binaryOp(lhs, rhs, s.server.And)
}

// OrBase64 performs homomorphic OR on two base64 ciphertexts.
func (s *BooleanService) OrBase64(lhs, rhs string) (string, error) {
	return s.binaryOp(lhs, rhs, s.server.Or)
}

// XorBase64 performs homomorphic XOR on two base64 ciphertexts.
func (s *BooleanService) XorBase64(lhs, rhs string) (string, error) {
	return s.binaryOp(lhs, rhs, s.server.Xor)
}

// NotBase64 performs homomorphic NOT on a base64 ciphertext.
func (s *BooleanService) NotBase64(input string) (string, error) {
	ct, err := deserialize(input)
	if err != nil {
		return "", err
	}
	defer ct.Close()

	out, err := s.server.Not(ct)
	if err != nil {
		return "", err
	}
	defer out.Close()
	return serializeToBase64(out)
}

// Close releases underlying key material.
func (s *BooleanService) Close() error {
	var err error
	if s.client != nil {
		err = s.client.Close()
		s.client = nil
	}
	if s.server != nil {
		if cerr := s.server.Close(); err == nil {
			err = cerr
		}
		s.server = nil
	}
	return err
}

type binaryOpFn func(lhs, rhs *Ciphertext) (*Ciphertext, error)

func (s *BooleanService) binaryOp(lhsBase64, rhsBase64 string, op binaryOpFn) (string, error) {
	lhs, err := deserialize(lhsBase64)
	if err != nil {
		return "", err
	}
	defer lhs.Close()

	rhs, err := deserialize(rhsBase64)
	if err != nil {
		return "", err
	}
	defer rhs.Close()

	out, err := op(lhs, rhs)
	if err != nil {
		return "", err
	}
	defer out.Close()

	return serializeToBase64(out)
}

func serializeToBase64(ct *Ciphertext) (string, error) {
	bytes, err := ct.Serialize()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func deserialize(ctBase64 string) (*Ciphertext, error) {
	if ctBase64 == "" {
		return nil, errors.New("ciphertext is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(ctBase64)
	if err != nil {
		return nil, err
	}
	return DeserializeCiphertext(raw)
}

// NewUint8Service generates keys for uint8 operations (client/server/public) and sets server key.
func NewUint8Service() (*Uint8Service, error) {
	ck, sk, err := GenerateUint8Keys()
	if err != nil {
		return nil, err
	}
	pk, err := NewUint8PublicKey(ck)
	if err != nil {
		return nil, err
	}
	return &Uint8Service{
		client: ck,
		server: sk,
		public: pk,
	}, nil
}

// Encrypt encrypts with client key and returns base64.
func (s *Uint8Service) Encrypt(value uint8) (string, error) {
	ct, err := EncryptUint8(s.client, value)
	if err != nil {
		return "", err
	}
	defer ct.Close()
	return serializeUint8ToBase64(ct)
}

// EncryptWithPublic encrypts with public key and returns base64.
func (s *Uint8Service) EncryptWithPublic(value uint8) (string, error) {
	ct, err := EncryptUint8Public(s.public, value)
	if err != nil {
		return "", err
	}
	defer ct.Close()
	return serializeUint8ToBase64(ct)
}

// Decrypt decrypts base64 ciphertext to uint8.
func (s *Uint8Service) Decrypt(ctBase64 string) (uint8, error) {
	ct, err := deserializeUint8(ctBase64)
	if err != nil {
		return 0, err
	}
	defer ct.Close()
	return DecryptUint8(s.client, ct)
}

// Add performs homomorphic addition (requires server key already set).
func (s *Uint8Service) Add(lhs, rhs string) (string, error) {
	return s.binaryUint8(lhs, rhs, Uint8Add)
}

// BitAnd performs homomorphic bitwise AND.
func (s *Uint8Service) BitAnd(lhs, rhs string) (string, error) {
	return s.binaryUint8(lhs, rhs, Uint8BitAnd)
}

// BitXor performs homomorphic bitwise XOR.
func (s *Uint8Service) BitXor(lhs, rhs string) (string, error) {
	return s.binaryUint8(lhs, rhs, Uint8BitXor)
}

// Close releases keys.
func (s *Uint8Service) Close() error {
	var err error
	if s.public != nil {
		err = s.public.Close()
		s.public = nil
	}
	if s.client != nil {
		if cerr := s.client.Close(); err == nil {
			err = cerr
		}
		s.client = nil
	}
	if s.server != nil {
		if cerr := s.server.Close(); err == nil {
			err = cerr
		}
		s.server = nil
	}
	return err
}

type uint8Op func(lhs, rhs *Uint8Ciphertext) (*Uint8Ciphertext, error)

func (s *Uint8Service) binaryUint8(lhsBase64, rhsBase64 string, op uint8Op) (string, error) {
	lhs, err := deserializeUint8(lhsBase64)
	if err != nil {
		return "", err
	}
	defer lhs.Close()

	rhs, err := deserializeUint8(rhsBase64)
	if err != nil {
		return "", err
	}
	defer rhs.Close()

	out, err := op(lhs, rhs)
	if err != nil {
		return "", err
	}
	defer out.Close()

	return serializeUint8ToBase64(out)
}

func serializeUint8ToBase64(ct *Uint8Ciphertext) (string, error) {
	bytes, err := ct.Uint8Serialize()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func deserializeUint8(ctBase64 string) (*Uint8Ciphertext, error) {
	if ctBase64 == "" {
		return nil, errors.New("ciphertext is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(ctBase64)
	if err != nil {
		return nil, err
	}
	return Uint8Deserialize(raw)
}
