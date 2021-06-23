package main

import (
  "os"
  "fmt"
  "log"
  "github.com/joho/godotenv"
)

func main() {
  err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	port := os.Getenv("PORT")
  host := os.Getenv("HOST")
  targetHost := os.Getenv("TARGETHOST")
  targetPort := os.Getenv("TARGETPORT")

  if len(os.Args) != 2 {
      fmt.Println("Usage: ", os.Args[0], "-client OR -server")
      os.Exit(1)
  }

  mode := os.Args[1]

  if mode == "-client" {
    client := NewClient()
    client.Initialize()
    client.ConnectTo(targetHost, targetPort)
    client.Run()
  } else if mode == "-server" {
    server := NewServer()
    server.Initialize()
    server.BindTo(host, port)
    server.Run()
  } else {
    fmt.Println("Usage: ", os.Args[0], "-client OR -server")
    os.Exit(1)
  }

  os.Exit(0)
}
