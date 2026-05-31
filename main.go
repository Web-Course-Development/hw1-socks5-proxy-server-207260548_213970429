package main

import (
	"flag"
	"fmt"
	"log"
	"net"
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// TODO: Implement SOCKS5 protocol
	// 1. Read client greeting and negotiate authentication method
	// make a buffer
	buffer_size := 2
	buffer := make([]byte, buffer_size)
	//read #buffer_size bytes from the connection into the buffer
	_, err := io.ReadFull(conn, buffer)
	//check for error
	if err != nil {
		log.Printf("failed to read to buffer: %v", err)
		return
	}
	//verify SOCKS (SOCKS5)
	if buffer[0] != 5 {
		log.Printf("wrong SOCKS version: %d", buffer[0])
		return
	}

	// 2. Perform authentication if required (when PROXY_USER env var is set)
	// 3. Read CONNECT request
	// 4. Connect to target server
	// 5. Send success/error reply
	// 6. Relay data between client and target
}
