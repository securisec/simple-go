package asymmetric

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
)

// GeneratePrivateKey generate a RSA private key
func GeneratePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}
	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// EncodePKCS1PrivateKeyToPEM encode RSA private key to PEM format.
// Includes the header RSA PRIVATE KEY in the conversion
func EncodePKCS1PrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)
	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}
	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)
	return privatePEM
}

// GetRsaPKCS1PrivateFromStr convert a RSA private key string to go RSA private key
// The private key should start with the header RSA PRIVATE KEY
func GetRsaPKCS1PrivateFromStr(privateKeyStr []byte) (*rsa.PrivateKey, error) {
	keyBlock, _ := pem.Decode(privateKeyStr)
	if keyBlock == nil {
		return nil, errors.New("No keys found")
	}
	keyBytes, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	return keyBytes, err
}

// EncodePublicKeyToPKIXPEM convert public key to PEM format.
// Will include PUBLIC KEY in the header
func EncodePublicKeyToPKIXPEM(keyPair *rsa.PrivateKey) ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&keyPair.PublicKey)
	if err != nil {
		return nil, err
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	// Public key in PEM format
	publicPEM := pem.EncodeToMemory(publicKeyBlock)
	return publicPEM, nil
}

// GetRsaPublicPKIXFromStr get public key from string public key.
// Public key should be in the format PUBLIC KEY
func GetRsaPublicPKIXFromStr(publicKeyStr []byte) (*rsa.PublicKey, error) {
	keyBlock, _ := pem.Decode(publicKeyStr)
	if keyBlock == nil {
		return nil, errors.New("No key block found")
	}
	pub, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, nil
	}
}

// EncryptOAEP encrypt payload with RSA OAEP and SHA256
func EncryptOAEP(payload []byte, key *rsa.PublicKey) ([]byte, error) {
	rnd := rand.Reader
	hash := sha256.New()
	// encrypt with OAEP
	ciperText, err := rsa.EncryptOAEP(hash, rnd, key, payload, nil)
	return ciperText, err
}

// DecryptOAEP decrypt payload with private key and SHA256.
// Openssl command: openssl pkeyutl -decrypt -inkey priv -in encrypted -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256
func DecryptOAEP(payload []byte, key *rsa.PrivateKey) ([]byte, error) {
	rnd := rand.Reader
	hash := sha256.New()
	// decrypt with OAEP
	plainText, err := rsa.DecryptOAEP(hash, rnd, key, payload, nil)
	return plainText, err
}

// EncryptPKCS1 encrypt payload with Public key PKCS1
func EncryptPKCS1(payload []byte, key *rsa.PublicKey) ([]byte, error) {
	ct, err := rsa.EncryptPKCS1v15(rand.Reader, key, payload)
	return ct, err
}

// DecryptPKCS1 decrypt payload with RSA private key.
// Openssl command: openssl rsautl -decrypt -inkey priv -in encrypted
func DecryptPKCS1(payload []byte, key *rsa.PrivateKey) ([]byte, error) {
	pt, err := rsa.DecryptPKCS1v15(rand.Reader, key, payload)
	return pt, err
}

// SignPKCS1SHA256 sign payload with private key
func SignPKCS1SHA256(payload string, key *rsa.PrivateKey) ([]byte, error) {
	// remove unwated characters and get sha256 hash of the payload
	replacer := strings.NewReplacer("\n", "", "\r", "", " ", "")
	msg := strings.TrimSpace(strings.ToLower(replacer.Replace(payload)))
	hashed := sha256.Sum256([]byte(msg))
	// sign the hased payload
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	// reutrn base64 encoded string
	return signature, err
}

// VerifyPKCS1SHA256 verify payload with public key
// payload: payload to verify
// signature: signature to verify against
func VerifyPKCS1SHA256(payload string, signature []byte, key *rsa.PublicKey) error {
	// remove unwated characters and get sha256 hash of the payload
	replacer := strings.NewReplacer("\n", "", "\r", "", " ", "")
	msg := strings.TrimSpace(strings.ToLower(replacer.Replace(payload)))
	hashed := sha256.Sum256([]byte(msg))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], signature)
}

// SignPKCS1SHA1 sign payload with private key
func SignPKCS1SHA1(payload string, key *rsa.PrivateKey) ([]byte, error) {
	// remove unwated characters and get sha1 hash of the payload
	replacer := strings.NewReplacer("\n", "", "\r", "", " ", "")
	msg := strings.TrimSpace(strings.ToLower(replacer.Replace(payload)))
	hashed := sha1.Sum([]byte(msg))
	// sign the hased payload
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, hashed[:])
	// reutrn base64 encoded string
	return signature, err
}

// VerifyPKCS1SHA1 verify payload with public key
// payload: payload to verify
// signature: signature to verify against
func VerifyPKCS1SHA1(payload string, signature []byte, key *rsa.PublicKey) error {
	// remove unwated characters and get sha1 hash of the payload
	replacer := strings.NewReplacer("\n", "", "\r", "", " ", "")
	msg := strings.TrimSpace(strings.ToLower(replacer.Replace(payload)))
	hashed := sha1.Sum([]byte(msg))
	return rsa.VerifyPKCS1v15(key, crypto.SHA1, hashed[:], signature)
}
