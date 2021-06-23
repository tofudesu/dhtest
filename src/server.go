package main

import (
  "fmt"
  "net"
  "os"
  "encoding/pem"
  "crypto/x509"
  "crypto/ecdsa"
)

// Client Connects -> Server sends ephemeral key -> Client sends ephemeral key -> Server sends Encryption Test -> Client sends encryption test
// Server message types
const(
  Ephemeral_Key = "EPHEMERAL_KEY"
  Challenge =     "CHALLENGE"
)

type Server struct {
  Sessions map[string]*Session

  listener *net.TCPListener
  tcpAddr *net.TCPAddr
  ServerRootPrivateKey  *ecdsa.PrivateKey
  ServerRootPublicKey   *ecdsa.PublicKey
}

func NewServer() *Server {
  return new(Server)
}

func (server *Server) Initialize() {
  // Throwaway testing key
  /*
  privateKeyPEM := []byte(`
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgs9E5jsJ5hJfA4uFf
eO56ehSylInDi3i3Pg8kt3oaNa+hRANCAAROrzmW0ZNtDq/XJSMVOVgyjDy8257w
k393WtUXfZMnqn2StCPRDxFnWtipmSGNAr/7fgudEIOkVigL9/fY+S34
-----END PRIVATE KEY-----
`)
*/

  privateKeyPEM := LoadFileToBytes("priv.key")

  block, _ := pem.Decode(privateKeyPEM)
  if block == nil || block.Type != "PRIVATE KEY" {
    fmt.Printf("private key PEM is invalid")
  }

  privateKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
  if err != nil {
    fmt.Printf("Failed to parse PEM block. %v", err)
  }

  server.Sessions = make(map[string]*Session)
  server.ServerRootPrivateKey = privateKeyInterface.(*ecdsa.PrivateKey)
}

func (server *Server) BindTo(host string, port string) {
  var err error
  server.tcpAddr, err = net.ResolveTCPAddr("tcp", host + ":" + port)
  if err != nil {
    checkError(err)
  }

  server.listener, err = net.ListenTCP("tcp", server.tcpAddr)
  if err != nil {
    checkError(err)
  }
}

func (server *Server) Run() {
  server.Listen()
}

func (server *Server) Listen() {
  for {
    conn, err := server.listener.Accept()
    if err != nil {
      fmt.Printf("Listener error.")
      os.Exit(1)
    }

    go server.handleClientConnection(conn)
  }
}

func (server *Server) handleClientConnection(conn net.Conn) {
  sess := NewSession(conn)
  sess.Initialize(SERVER)

  server.Sessions[conn.RemoteAddr().String()] = sess
  //server.Sessions = append(server.Sessions, sess)
  for {
    if sess.isOpen == false {
      delete(server.Sessions, sess.Connection.RemoteAddr().String());
      fmt.Printf("Session removed. \n")
      return
    }
    sess.Update()
  }
}
