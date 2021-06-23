package main

import (
  "os"
  "net"
  "fmt"
  "encoding/json"
  "crypto/rand"
  "crypto/sha256"
  "crypto/elliptic"
)

type SessionState string
// Session state enum
const(
  SESSION_IDLE SessionState =     "SESSION_IDLE"
  SESSION_ENCRPYTED =             "SESSION_ENCRPYTED"
  PENDING_SERVER_AUTHENTICATION = "PENDING_SERVER_AUTHENTICATION"
  PENDING_SERVER_EPHEMERAL_KEY =  "PENDING_SERVER_EPHEMERAL_KEY"
  PENDING_CLIENT_EPHEMERAL_KEY =  "PENDING_CLIENT_EPHEMERAL_KEY"
  PENDING_ENCRYPTION_TEST =       "PENDING_ENCRYPTION_TEST"
)

type MessageType string
// Session message types
const(
  PLAINTEXT MessageType = "PLAINTEXT"
  SIGNED =                "SIGNED"
  EPHEMERAL =             "EPHEMERAL"
  ENCRYPTED =             "ENCRYPTED"
  TEST =                  "TEST"
  KEEPALIVE =             "KEEPALIVE"
  BROADCAST =             "BROADCAST"
)

type SessionType string
const(
  CLIENT SessionType =  "CLIENT" // If we created this session to connect to a remote machine then this session is a client type
  SERVER =              "SERVER"
)

type Message struct {
  MessageType  MessageType
  Data         []byte
}

type EncryptedData struct {
  Data  []byte
  Nonce []byte
}

type Session struct {
  Connection net.Conn
  JsonEncoder *json.Encoder
  JsonDecoder *json.Decoder

  SessionType   SessionType
  SessionState  SessionState

  // Ephemeral keys for Perfect Forward Secrecy.
  LocalEphemeralPrivateKey  *ellipticPrivateKey
  LocalEphemeralPublicKey   *ellipticPublicKey
  RemoteEphemeralPublicKey  *ellipticPublicKey

  // AESkey is generated via sha256(agreed secret)
  // The nonce in AES-GCM has to be unique for every message.
  // Nonce is incremented after every message.
  AESKey  []byte // 32 bytes
  Nonce   []byte  // 12 bytes

  isOpen bool
}

func (sess *Session) EncryptMessage(message Message) Message {
  fmt.Printf("Encrypting [%s] \n", message.MessageType)
  return EncryptMessage(message, sess.AESKey, &sess.Nonce)
}

func (sess *Session) SendMessage(message Message) {
  if(sess.Connection != nil) {
    fmt.Printf("Sent [%s] \n", message.MessageType)
    sess.JsonEncoder.Encode(message)
  }
}

func EncryptMessage(message Message, aeskey []byte, nonce *[]byte) Message {
  // EncryptData increments the nonce so we need to keep track of it here
  originalNonce := nonce

  // Convert message to bytes and encrypt
  messageBytes, _ := json.Marshal(message)
  ciphertext := EncryptAESGCM(aeskey, *nonce, messageBytes)

  encryptedData := EncryptedData{Data: ciphertext, Nonce: *originalNonce }
  encryptedDataBytes, _ := json.Marshal(encryptedData)

  // Wrap encryptedDataBytes into a Message with type ENCRYPTED and return
  return Message{MessageType: ENCRYPTED, Data: encryptedDataBytes }
}

func DecryptMessage(message Message, aeskey []byte) Message {
  // Extract EncryptedData struct
  var encryptedData EncryptedData
  json.Unmarshal(message.Data, &encryptedData)

  // Decrypt encryptedData
  decryptedBytes := DecryptAESGCM(aeskey, encryptedData.Nonce, encryptedData.Data)

  // Unmarshal Message from decryptedBytes
  var decryptedMessage Message
  json.Unmarshal(decryptedBytes, &decryptedMessage)

  return decryptedMessage
}

func NewSession(conn net.Conn) *Session {
  sess := new(Session)
  sess.Connection = conn
  sess.JsonEncoder = json.NewEncoder(conn)
  sess.JsonDecoder = json.NewDecoder(conn)
  return sess
}

func (sess *Session) Initialize(sessionType SessionType) {
  fmt.Printf("Serving: %s\n", sess.Connection.RemoteAddr().String())
  sess.isOpen = true
  // Generate new ephemeral key pair. Ephemeral keys are used for only one session and discarded.
  // Compromise of this key will permit access only to the data from this session.
  // This is the Ephemeral part of Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) and is essential for perfect forward secrecy.
  var err error
  sess.LocalEphemeralPrivateKey, sess.LocalEphemeralPublicKey, err = GenerateECKeyPair(rand.Reader)
  if err != nil {
    fmt.Printf("Failed to generate key pair.")
    os.Exit(0)
  }

  sess.SessionType = sessionType
  sess.SessionState = SESSION_IDLE
  sess.Nonce = GenerateNonce()
}

func (sess *Session) Update() {
  // Check for death
  for sess.isOpen {
    sess.UpdateState()
    sess.UpdateConnection()
  }
}

func (sess *Session) UpdateConnection () {
  var message Message
  err := sess.JsonDecoder.Decode(&message);
  if err != nil {
    fmt.Printf("Conn error: %v", err)
    sess.Close()
    return
  }

  sess.handleMessage(message)
}

func (sess *Session) UpdateState() {
  switch sess.SessionState {
    case SESSION_IDLE:
      // Send server auth to client
      if sess.SessionType == SERVER {
        sess.sendEphemeralKey()
        sess.SessionState = PENDING_CLIENT_EPHEMERAL_KEY
      }

      // Do nothing, wait for server auth
      if sess.SessionType == CLIENT {
        sess.SessionState = PENDING_SERVER_EPHEMERAL_KEY
      }
      break
    case PENDING_ENCRYPTION_TEST:
      break
    case PENDING_SERVER_AUTHENTICATION:
      break
    case PENDING_SERVER_EPHEMERAL_KEY:
      break
    case PENDING_CLIENT_EPHEMERAL_KEY:
      break
    case SESSION_ENCRPYTED:
      // Keep alive not implemented
      break
  default:
  }
}

func (sess *Session) handlePlaintextMessage(message Message) {
  // Custom functionality not implemented
}

func (sess *Session) handleMessage(message Message) {
  fmt.Printf("Received Message: %s \n", message.MessageType)

  switch message.MessageType {
  case SIGNED:
    sess.handleSignedMessage(message)
    break
  case ENCRYPTED:
    sess.handleEncryptedMessage(message)
    break
  case PLAINTEXT:
    sess.handlePlaintextMessage(message)
    break
  case EPHEMERAL:
    sess.handleEphemeralKey(message)
    break
  case TEST:
    sess.handleEncryptionTest(message)
    break
	default:
	}
}

func (sess *Session) handleEncryptedMessage(message Message) {
  decryptedMessage := DecryptMessage(message, sess.AESKey)
  sess.handleMessage(decryptedMessage)
}

func (sess *Session) handleSignedMessage(message Message) Message {
  return Message{}
}

func (sess *Session) handleEphemeralKey(message Message) {
  sess.RemoteEphemeralPublicKey = new(ellipticPublicKey)
  sess.RemoteEphemeralPublicKey.Curve = elliptic.P256()
  sess.RemoteEphemeralPublicKey.X, sess.RemoteEphemeralPublicKey.Y = elliptic.UnmarshalCompressed(elliptic.P256(), message.Data)

  // Generate shared secret and AESKey
  sess.AESKey, _ = GenerateSharedSecret(sess.LocalEphemeralPrivateKey, sess.RemoteEphemeralPublicKey)

  // If we're a client we respond with our own ephemeral key
  if sess.SessionType == CLIENT {
    sess.sendEphemeralKey()
  }

  // If we're a server then we respond with an encryption test
  if sess.SessionType == SERVER {
    sess.sendEncryptionTest()
  }

  sess.SessionState = PENDING_ENCRYPTION_TEST
}

func (sess *Session) sendEphemeralKey() {
  key_data := elliptic.MarshalCompressed(elliptic.P256(), sess.LocalEphemeralPublicKey.X, sess.LocalEphemeralPublicKey.Y)
  message := Message{MessageType: EPHEMERAL, Data: key_data }

  sess.SendMessage(message)
}

func (sess *Session) handleEncryptionTest(message Message) {
  localHash := sha256.Sum256(sess.AESKey)

  var remoteHash [32]byte
  json.Unmarshal(message.Data, &remoteHash)

  if remoteHash != localHash {
    // Encryption test failed -> kill connection
    sess.Close()
    return
  }

  // If CLIENT, respond with our test
  if sess.SessionType == CLIENT {
    sess.sendEncryptionTest()
  }

  sess.SessionState = SESSION_ENCRPYTED
  fmt.Printf("Test match. Encrypted connection established. Closing connection. \n")
  sess.Close()

  /*time.AfterFunc(time.Second*3, func() {
      sess.Close()
  })
  defer timer.Stop()
  */
}

func (sess *Session) sendEncryptionTest() {
  hash := sha256.Sum256(sess.AESKey)

  hashBytes, _ := json.Marshal(hash)
  testMessage := Message{MessageType: TEST, Data: hashBytes }

  // Send as encrypted
  encryptedMessage := sess.EncryptMessage(testMessage)
  sess.SendMessage(encryptedMessage)
}

func (sess *Session) Close() {
  // Disconnect the conn
  fmt.Printf("Session closed. \n")
  sess.Connection.Close()
  sess.isOpen = false
}
