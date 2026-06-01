package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"encoding/binary"
	"io"
	"os"
	"sync"

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
	req_method, err := negotiateAuth(conn)
	if err != nil {
		return
	}

	// 2. Perform authentication if required (when PROXY_USER env var is set)
	if req_method == 0x02 {
		err = authenticateUserPass(conn)
		if err != nil {
			return
		}
	}

	// 3. Read CONNECT request
	// 4. Connect to target server
	// 5. Send success/error reply
	target_conn, err := handleConnect(conn)
	if err != nil {
		return
	}
	// ensure the target connection gets closed when we are done
	defer target_conn.Close()

	// 6. Relay data between client and target
	relay(conn, target_conn)
}

func negotiateAuth(conn net.Conn) (byte, error) {
	// make a buffer
	buffer_size := 2
	buffer := make([]byte, buffer_size)
	
	// read #buffer_size bytes from the connection into the buffer
	_, err := io.ReadFull(conn, buffer)
	
	// check for error
	if err != nil {
		log.Printf("failed to read to buffer: %v", err)
		return 0, err
	}
	
	// verify SOCKS (SOCKS5) (note to self: use hex instead of decimals, it's apparently customary in networks)
	if buffer[0] != 0x05 {
		log.Printf("wrong SOCKS version: %x", buffer[0])
		return 0, fmt.Errorf("wrong SOCKS version")
	}

	// number of methods is stored in the second byte of the buffer
	methods_num := int(buffer[1])
	
	// new buffer to hold enough methods
	methods := make([]byte, methods_num)
	
	// read to methods buffer
	_, err = io.ReadFull(conn, methods)
	if err != nil {
		log.Printf("failed to read methods: %v", err)
		return 0, err
	}

	// get method request
	// set default = no Auth
	req_method := byte(0x00)
	if os.Getenv("PROXY_USER") != "" {
		// 2 requires user/pass
		req_method = 0x02
	}
	
	// loop through to check if we support the methods that the client wants
	supported := false
	for _, m := range methods {
		if m == req_method {
			supported = true
			break
		}
	}
	
	// reply to client
	if supported == true {
		_, err = conn.Write([]byte{0x05, req_method})
		if err != nil {
			log.Printf("failed to write method selection: %v", err)
			return 0, err
		}
		return req_method, nil
	} else {
		// we don't support the required method (0xFF for non supported methods)
		conn.Write([]byte{0x05, 0xFF})
		log.Printf("client doesn't support required auth method")
		return 0, fmt.Errorf("unsupported auth method")
	}
}

func authenticateUserPass(conn net.Conn) error {
	// read the auth sub-neg version and username length
	auth_buffer_size := 2
	auth_buffer := make([]byte, auth_buffer_size)
	_, err := io.ReadFull(conn, auth_buffer)
	if err != nil {
		log.Printf("failed to read auth header: %v", err)
		return err
	}

	// verify auth version (must be 0x01 for sub-neg NOT 0x05)
	if auth_buffer[0] != 0x01 {
		log.Printf("wrong auth version: %x", auth_buffer[0])
		return fmt.Errorf("wrong auth version")
	}

	// username length is the second byte
	ulen := int(auth_buffer[1])
	
	// read the username
	uname_buffer := make([]byte, ulen)
	_, err = io.ReadFull(conn, uname_buffer)
	if err != nil {
		log.Printf("failed to read username: %v", err)
		return err
	}
	
	// convert username bytes to a readable string
	uname := string(uname_buffer)

	// read password length (1 byte)
	plen_buffer := make([]byte, 1)
	_, err = io.ReadFull(conn, plen_buffer)
	if err != nil {
		log.Printf("failed to read password length: %v", err)
		return err
	}
	plen := int(plen_buffer[0])

	// read the password
	passwd_buffer := make([]byte, plen)
	_, err = io.ReadFull(conn, passwd_buffer)
	if err != nil {
		log.Printf("failed to read password: %v", err)
		return err
	}
	
	// convert password bytes to a readable string
	passwd := string(passwd_buffer)

	// verify credentials against environment variables
	expected_user := os.Getenv("PROXY_USER")
	expected_pass := os.Getenv("PROXY_PASS")

	if uname == expected_user && passwd == expected_pass {
		// success: version 0x01 status 0x00
		conn.Write([]byte{0x01, 0x00})
		log.Printf("authentication successful for user: %s", uname)
		return nil
	} else {
		// failure: version 0x01 status 0x01 (or any non zero)
		conn.Write([]byte{0x01, 0x01})
		log.Printf("authentication failed for user: %s", uname)
		return fmt.Errorf("authentication failed")
	}
}

func handleConnect(conn net.Conn) (net.Conn, error) {
	// read the first 4 bytes of the connect request (ver, cmd, rsv, atyp)
	req_buffer_size := 4
	req_buffer := make([]byte, req_buffer_size)
	_, err := io.ReadFull(conn, req_buffer)
	if err != nil {
		log.Printf("failed to read connect request header: %v", err)
		return nil, err
	}

	// verify SOCKS version again
	if req_buffer[0] != 0x05 {
		log.Printf("wrong SOCKS version in connect request: %x", req_buffer[0])
		return nil, fmt.Errorf("wrong SOCKS version")
	}

	// verify command is CONNECT (0x01)
	if req_buffer[1] != 0x01 {
		// we only support CONNECT (0x01) reject anything else
		log.Printf("unsupported command: %x", req_buffer[1])
		return nil, fmt.Errorf("unsupported command")
	}

	// save the address type for the next step (IPv4 is 0x01 domain is 0x03)
	atyp := req_buffer[3]

	// variable to hold the parsed destination address as a string
	dest_address := ""

	// read the destination address based on atyp
	if atyp == 0x01 {
		// IPv4: 4 bytes
		ipv4_buffer := make([]byte, 4)
		_, err = io.ReadFull(conn, ipv4_buffer)
		if err != nil {
			log.Printf("failed to read IPv4 address: %v", err)
			return nil, err
		}
		// format as a standard IP string using net.IP
		dest_address = net.IP(ipv4_buffer).String()
		
	} else if atyp == 0x03 {
		// domain Name: first byte is length then the string itself
		domain_len_buffer := make([]byte, 1)
		_, err = io.ReadFull(conn, domain_len_buffer)
		if err != nil {
			log.Printf("failed to read domain length: %v", err)
			return nil, err
		}
		domain_len := int(domain_len_buffer[0])
		
		domain_buffer := make([]byte, domain_len)
		_, err = io.ReadFull(conn, domain_buffer)
		if err != nil {
			log.Printf("failed to read domain name: %v", err)
			return nil, err
		}
		dest_address = string(domain_buffer)
		
	} else {
		// we're not asked to support IPv6 (0x04) for this homework
		log.Printf("unsupported address type: %x", atyp)
		return nil, fmt.Errorf("unsupported address type")
	}

	// read the destination port (2 bytes)
	port_buffer := make([]byte, 2)
	_, err = io.ReadFull(conn, port_buffer)
	if err != nil {
		log.Printf("failed to read destination port: %v", err)
		return nil, err
	}

	// convert the 2 bytes to a uint16 using BigEndian
	dest_port := binary.BigEndian.Uint16(port_buffer)

	// format the final target string like "host:port"
	target := fmt.Sprintf("%s:%d", dest_address, dest_port)
	log.Printf("client wants to connect to: %s", target)

	// use net.Dial to establish the TCP connection to the destination
	target_conn, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("failed to connect to target %s: %v", target, err)
		// send error reply (0x01 = general failure)
		// format: VER, REP, RSV, ATYP, BND.ADDR (4 bytes), BND.PORT (2 bytes)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return nil, err
	}
	
	log.Printf("successfully connected to target: %s", target)

	// (error reply is in previous step)
	// 0x00 means success. The assignment allows us to send all zeros for the bound address and port.
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		log.Printf("failed to send success reply: %v", err)
		target_conn.Close()
		return nil, err
	}
	
	log.Printf("connection established and client notified")
	return target_conn, nil
}

func relay(conn net.Conn, target_conn net.Conn) {
	// use a WaitGroup to handle our concurrent goroutines
	var wg sync.WaitGroup
	
	// we have 2 directions to relay (client -> target and target -> client)
	wg.Add(2)

	// client -> target
	go func() {
		defer wg.Done()
		// copy data from the client (conn) to the target (target_conn)
		io.Copy(target_conn, conn)
		
		// signal EOF by closing the write half of the conn
		if tcp_conn, ok := target_conn.(*net.TCPConn); ok {
			tcp_conn.CloseWrite()
		}
	}()

	// target -> client
	go func() {
		defer wg.Done()
		// copy data from the target (target_conn) back to the client (conn)
		io.Copy(conn, target_conn)
		
		// signal EOF by closing the write half of the conn
		if tcp_conn, ok := conn.(*net.TCPConn); ok {
			tcp_conn.CloseWrite()
		}
	}()

	// block and wait here until both goroutines finish
	wg.Wait()
	log.Printf("relay finished connection closed")
}