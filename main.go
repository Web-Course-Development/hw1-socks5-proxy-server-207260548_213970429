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
	//verify SOCKS (SOCKS5) (note to self: use hex instead of decimals, it's apparently customary in networks)
	if buffer[0] != 0x05 {
		log.Printf("wrong SOCKS version: %x", buffer[0])
		return
	}

	//number of methods is stored in the second byte of the buffer
	methods_num := int(buffer[1])
	//new buffer to hold enough methods
	methods := make([]byte, methods_num)
	//read to methods buffer
	_, err = io.ReadFull(conn, methods)
	if err != nil {
		log.Printf("failed to read methods: %v", err)
		return
	}

	//get method request
	//set default = no Auth
	req_method := byte(0x00)
	if os.Getenv("PROXY_USER") != "" {
		// 2 requires user/pass
		req_method = 0x02
	}
	//loop through to check if we support the methods that the client wants
	supported := false
	for _, m := range methods {
		if m == req_method {
			supported = true
			break
		}
	}
	//reply to client
	if supported == true {
		_, err = conn.Write([]byte{0x05, req_method})
		if err != nil {
			log.Printf("failed to write method selection: %v", err)
			return
		}
	} else {
		// we don't support the required method (0xFF for no supported methods)
		conn.Write([]byte{0x05, 0xFF})
		log.Printf("client doesn't support required auth method")
		return
	}

	// 2. Perform authentication if required (when PROXY_USER env var is set)
	// 3. Read CONNECT request
	// 4. Connect to target server
	// 5. Send success/error reply
	// 6. Relay data between client and target
}
