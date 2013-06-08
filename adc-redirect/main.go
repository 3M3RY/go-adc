// Copyright © 2013 Emery Hemingway

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
)

import "code.google.com/p/go-adc/adc"

var (
	port         = flag.Int("port", 1511, "port to listen for incoming connections on")
	target       = flag.String("target", "adc://localhost:1511", "hub to redirect clients to")
	certFilename = flag.String("cert", "", "TLS certificate file")
	keyFilename  = flag.String("key", "", "TLS key file")
)

func main() {
	flag.Parse()
	var ln net.Listener
	var err error
	if *certFilename != "" && *keyFilename == "" {
		fmt.Println("missing key argument")
		flag.Usage()
		os.Exit(-1)
	}
	if *certFilename == "" && *keyFilename != "" {
		fmt.Println("missing cert argument")
		flag.Usage()
		os.Exit(-1)
	}

	if *certFilename == "" && *keyFilename == ""{
		ln, err = net.Listen("tcp", fmt.Sprintf(":%d", *port))
	} else {
		cert, err := tls.LoadX509KeyPair(*certFilename, *keyFilename)
		if err != nil {
			fmt.Println("TLS error:", err)
			os.Exit(-1)
		}
		config := &tls.Config{Certificates: []tls.Certificate{cert}}
		ln, err = tls.Listen("tcp", fmt.Sprintf(":%d", *port), config)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(c io.ReadWriteCloser) {
	conn := adc.NewConn(c)
	defer conn.Close()

	msg, err := conn.ReadMessage()
	if err != nil {
		return
	}
	if msg.Cmd != "SUP" {
		return
	}
	conn.WriteLine("ISUP ADBASE ADTIGR")
	conn.WriteLine("ISID AAAX")
	conn.WriteLine("IINF CT32 NIRedirector VEgo-adc\\sredirector\\s0.1")

	msg, err = conn.ReadMessage()
	if err != nil {
		return
	}
	if msg.Cmd != "INF" {
		return
	}

	conn.WriteLine("IMSG This\\shub\\shas\\smove\\sto:\\s%s", *target)
	conn.WriteLine("IMSG You\\sare\\sbeing\\sredirected...")
	conn.WriteLine("IQUI AAAX RD%s", *target)
}
