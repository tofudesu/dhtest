package main

import (
  "crypto/elliptic"
  "math/big"
  "io"
  "io/ioutil"
  "fmt"
  "crypto/aes"
  "crypto/ecdsa"
  "crypto/cipher"
  "crypto/rand"
  "crypto/sha256"
)

type MessageWrapper struct {
  JSONPacketType  string
  Data            []byte
}

func wrapData(packetType string, data []byte) MessageWrapper{
  return MessageWrapper{JSONPacketType: packetType, Data: data}
}

func checkError(err error) {
  if err != nil {
    fmt.Println("Fatal error ", err.Error())
  }
}

type ellipticPrivateKey struct {
	D []byte
}

type ellipticPublicKey struct {
	Curve elliptic.Curve
	X, Y *big.Int
}

func GenerateNonce() []byte {
  nonce := make([]byte, 12)
  if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
    checkError(err)
  }

  return nonce
}

func IncrementNonce(nonce []byte) []byte {
  bigInt := new(big.Int)
  bigInt.SetBytes(nonce)

  // fmt.Printf("Old nonce: %s \n", bigInt)

  increment, _ := new(big.Int).SetString("1", 12)
  bigInt.Add(bigInt, increment)

  // fmt.Printf("New nonce: %s \n", bigInt)

  return bigInt.Bytes()
}

func EncryptData(key []byte, nonce *[]byte, data []byte) []byte {
  return EncryptAESGCM(key, *nonce, data)
}

func DecryptData(key []byte, nonce []byte, data []byte) []byte {
  return DecryptAESGCM(key, nonce, data)
}

func EncryptAESGCM(key []byte, nonce []byte, data []byte) []byte {
  // block
  block, err := aes.NewCipher(key)
  checkError(err)

  // cipher
  aesgcm, err := cipher.NewGCM(block)
  checkError(err)

  // encrypt
  ciphertext := aesgcm.Seal(nil, nonce, data, nil)

  return ciphertext
}

func DecryptAESGCM(key []byte, nonce []byte, data []byte) []byte {
  // block
  block, err := aes.NewCipher(key)
  checkError(err)

  // cipher
  aesgcm, err := cipher.NewGCM(block)
  checkError(err)

  // decrypt
  plaintext, err := aesgcm.Open(nil, nonce, data, nil)
  checkError(err)

  return plaintext
}

func LoadFileToBytes(filename string) []byte {
  data, err := ioutil.ReadFile(filename)
  if err != nil {
      fmt.Println("File reading error", err)
      return nil
  }

  return data
}

func GenerateECDSAKeyPair(rand io.Reader) (*ecdsa.PrivateKey, error) {
  key, _ := ecdsa.GenerateKey(elliptic.P256(), rand)
  return key, nil
}

func GenerateECKeyPair(rand io.Reader) (*ellipticPrivateKey, *ellipticPublicKey, error) {
  var d []byte
  curve := elliptic.P256()
  d, x, y, err := elliptic.GenerateKey(curve, rand)
  if err != nil {
    return nil, nil, err
  }

  var private_key = new(ellipticPrivateKey)
  private_key.D = d

  var public_key = new(ellipticPublicKey)
  public_key.Curve = curve
  public_key.X = x
  public_key.Y = y

  return private_key, public_key, nil
}

func GenerateSharedSecret(privateKey *ellipticPrivateKey, publicKey *ellipticPublicKey) ([]byte, error) {
  ss, _ := elliptic.P256().ScalarMult(publicKey.X, publicKey.Y, privateKey.D)
  data := ss.Bytes()
  hash := sha256.Sum256(data)
  fmt.Printf("Shared secret: %x\n",  hash)
  key := hash[:]
  return key, nil
}
