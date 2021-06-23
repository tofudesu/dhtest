package main

import (
  "os"
  "fmt"
  "net"
  "encoding/pem"
  "crypto/x509"
  "crypto/ecdsa"
)

type Client struct {
  Sessions map[string]*Session

  ServerRootPublicKey   *ecdsa.PublicKey
}

func NewClient() *Client {
  return new(Client)
}

func (client *Client) Initialize() {
  client.Sessions = make(map[string]*Session)

  // Server root public key retrieved via third party auth service or embedded into the client
  // This key is used to verify server authenticity AFTER the ECDHE tunnel is established
  // In this case the public key is shipped with the client
  publicKeyPEM := LoadFileToBytes("pub.key")

  block, _ := pem.Decode(publicKeyPEM)
  if block == nil || block.Type != "PUBLIC KEY" {
    fmt.Printf("ServerRootPublicKey PEM is invalid")
  }

  serverRootPublicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
  if err != nil {
    fmt.Printf("Failed to parse ServerRootPublicKey %v", err)
  }

  client.ServerRootPublicKey = serverRootPublicKeyInterface.(*ecdsa.PublicKey)
}

func (client *Client) Run() {
  fmt.Println("Client running. \n")

  for {
    for _, sess := range client.Sessions {
      if sess.isOpen == false {
        delete(client.Sessions, sess.Connection.RemoteAddr().String())
        fmt.Println("Session removed. \n")
        return
      }

      sess.Update()
    }
  }
}

func (client *Client) ConnectTo(targetHost string, targetPort string) {
  conn, err := net.Dial("tcp", targetHost + ":" + targetPort)
  if err != nil {
    checkError(err)
    os.Exit(0)
  }

  sess := NewSession(conn)
  sess.Initialize(CLIENT)
  client.Sessions[conn.RemoteAddr().String()] = sess
}
