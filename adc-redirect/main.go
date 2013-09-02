// Copyright © 2013 Emery Hemingway


package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

import "github.com/3M3RY/go-adc/adc"

var (
	port            = flag.Int("port", 1511, "port to listen for incoming connections on")
	messageFilename = flag.String("message", "", "file containing a message to send to clients")
	target          = flag.String("target", "", "hub to redirect clients to")
	certFilename    = flag.String("cert", "", "TLS certificate file")
	keyFilename     = flag.String("key", "", "TLS key file")
	logRedirects    = flag.Bool("log", false, "log clients to Stdout")
	redirectLog     *log.Logger
	actions         []action
)

type funcConfig struct {
	f func(c *clientConfig, d time.Duration)
	d time.Duration
}

type clientConfig struct {
	nick    string
	ip      string
	session *adc.Session
}

type action interface {
	run(c *clientConfig)
}

type sleepAction struct {
	d time.Duration
}

func (a *sleepAction) run(c *clientConfig) { time.Sleep(a.d) }

type formatAction struct {
	s string
}

func (a formatAction) run(c *clientConfig) {
	a.s = strings.Replace(a.s, "%t", *target, -1)
	a.s = strings.Replace(a.s, "%n", c.nick, -1)
	a.s = strings.Replace(a.s, "%a", c.ip, -1)
	a.s = strings.Replace(a.s, "%%", "%", -1)
	c.session.WriteLine("IMSG %s", a.s)
}

type msgAction struct {
	s string
}

func (a *msgAction) run(c *clientConfig) {
	c.session.WriteLine("IMSG %s", a.s)
}

func main() {
	flag.Parse()
	if *target == "" {
		fmt.Println("no redirect target specified")
		flag.Usage()
		fmt.Print("\n")
		messageUsage()
		os.Exit(-1)
	}

	if *messageFilename != "" {
		msgFile, err := os.Open(*messageFilename)
		if err != nil {
			fmt.Println("Error parsing message,", err)
			os.Exit(-1)
		}
		r := bufio.NewReader(msgFile)
		for {
			s, err := r.ReadString('\n')
			s = strings.Replace(s, "\n", "", -1)
			if err != nil {
				if err == io.EOF {
					break
				} else {
					fmt.Println("Error parsing message,", err)
					os.Exit(-1)
				}
			}

			if len(s) > 1 && s[0] == uint8('!') {
				d, err := time.ParseDuration(s[1:])
				if err != nil {
					fmt.Println("Error parsing message,", err)
					os.Exit(-1)
				}
				actions = append(actions, &sleepAction{d})
				continue
			}

			s = strings.Replace(s, " ", "\\s", -1)
			if strings.Contains(s, "%") {
				actions = append(actions, &formatAction{s})
				continue
			}
			actions = append(actions, &msgAction{s})
		}
	}

	if *logRedirects {
		redirectLog = log.New(os.Stdout, log.Prefix(), log.Flags())
	}
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

	if *certFilename == "" && *keyFilename == "" {
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

func messageUsage() {
	fmt.Println("A message should contain the message you want displayed to clients.")
	fmt.Println("The redirector will make substitutions for the following tokens:")
	fmt.Println("\t %t - the redirect taget")
	fmt.Println("\t %n - Nickname of the user")
	fmt.Println("\t %a - IP address of the user")
	fmt.Println("\t %% - Becomes '%'")
	fmt.Println("A line starting with '!' followed by a number and a unit suffix will")
	fmt.Println("instruct the redirector to wait before continuing. Valid time units are")
	fmt.Println("'ns', 'us' (or 'µs'), 'ms', 's', 'm', 'h'.")
}

func handleConnection(nc net.Conn) {
	session := adc.NewSession(nc)
	defer session.Close()

	msg, err := session.ReadMessage()
	if err != nil {
		return
	}
	if msg.Cmd != "SUP" {
		return
	}
	session.WriteLine("ISUP ADBASE ADTIGR")
	session.WriteLine("ISID AAAX")
	session.WriteLine("IINF CT32 NIRedirector VEgo-adc\\sredirector\\s0.1")

	msg, err = session.ReadMessage()
	if err != nil {
		return
	}
	if msg.Cmd != "INF" {
		return
	}

	var id string
	c := &clientConfig{ip: nc.RemoteAddr().String(), session: session}
	for _, field := range msg.Params[1:] {
		switch field[:2] {
		case "ID":
			id = field[2:]
			if c.nick != "" {
				break
			}
		case "NI":
			c.nick = field[2:]
			if id != "" {
				break
			}
		}
	}
	if *logRedirects {
		redirectLog.Println(id, c.ip, c.nick)
	}
	for _, a := range actions {
		a.run(c)
	}
	session.WriteLine("IQUI AAAX RD%s", *target)
}
