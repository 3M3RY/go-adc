// Copyright © 2013 Emery Hemingway
// Released under the terms of the GPL-3

package adc

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"errors"
	"fmt"
	"github.com/3M3RY/go-tiger"
	"hash"
	"net"
	"net/url"
	"strings"
)

var (
	errorKeyprint     = errors.New("KEYP verification failed, potential man-in-the-middle attack detected")
	errorSUP          = errors.New("Did not receive BASE SUP before SID")
	errorNoCommonHash = errors.New("no common hash function (no Tiger)")
)

func connectToHub(url *url.URL) (*Session, error) {
	// check for and process a keyprint parameter in url
	var err error
	var digest hash.Hash
	var keyPrint []byte
	q := url.Query()
	if v, ok := q["kp"]; ok {
		params := strings.Split(v[0], "/")
		switch params[0] {
		case "SHA256":
			digest = sha256.New()
			keyPrint, err = base32.StdEncoding.DecodeString(params[1] + "====")
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New(params[0] + " KEYP verification is not supported")
		}
	}
	// process adc: or adcs:
	switch url.Scheme {
	case "adc":
		if digest != nil {
			return nil, Error("KEYP specified but adcs:// was not")
		}
		conn, err := net.Dial("tcp", url.Host)
		if err != nil {
			return nil, err
		}
		return NewSession(conn), nil

	case "adcs":
		conn, err := tls.Dial("tcp", url.Host, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, err
		}
		if digest != nil {
			digest.Write(conn.ConnectionState().PeerCertificates[0].Raw)
			if !bytes.Equal(digest.Sum(nil), keyPrint) {
				return nil, errorKeyprint
			}
		}
		return NewSession(conn), nil

	default:
		return nil, errors.New("unrecognized URL format " + url.String())
	}
}

// NewHubClient connects to a ADC hub url as the user identified by Private ID pid
func NewHubClient(url *url.URL, pid *Identifier, inf FieldMap, password string) (Client, error) {
	session, err := connectToHub(url)
	if err != nil {
		return nil, err
	}

	if inf == nil {
		inf = make(FieldMap)
	}
	c := &client{
		session:       session,
		pid:           pid,
		inf:           inf,
		handlers:      make(map[string]ClientMessageHandler),
		tokenHandlers: make(map[string]map[string]ClientMessageHandler),
		features:      make(map[string]bool),
		egress:        make(chan Messager),
		ingress:       make(chan *ReceivedMessage, 1024),
		err:           make(chan error), // Unbuffered to block
		peers:         make(map[string]*Peer),
	}
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()

	go func() {
		var msg *ReceivedMessage
		var err error
		for {
			msg, err = c.session.ReadMessage()
			if err == nil {
				c.ingress <- msg
			} else {
				c.err <- err
			}
		}
	}()

	var invalid []*ReceivedMessage
	err = hubProtocolState(c, invalid)
	if err != nil {
		return nil, err
	}
	err = hubIdentifyState(c)
	if err != nil {
		return nil, err
	}
	err = hubVerifyState(c, invalid, password)
	if err != nil {
		return nil, err
	}
	go hubNormalState(c, invalid)
	return c, nil
}

func hubProtocolState(c *client, invalid []*ReceivedMessage) error {
	//fmt.Println("PROTOCOL")
	c.session.writeLine("HSUP ADBASE ADTIGR")
	for {
		select {
		case msg := <-c.ingress:
			switch msg.Command {
			case "STA":
				if msg.Params[0][0] != '0' {
					return fmt.Errorf(msg.String())
				}
				invalid = append(invalid, msg)

			case "SUP":
				for _, word := range msg.Params {
					switch word[:2] {
					case "AD":
						c.features[word[2:]] = true
					default:
						return fmt.Errorf("unknown word %v in SUP", word)
					}
				}

			case "SID":
				if !c.features["BASE"] {
					c.session.writeLine("HSTA 244 FCBASE")
					return errorSUP
				}
				if !c.features["TIGR"] {
					c.session.writeLine("HSTA 247 client\\sonly\\ssupports\\sTGR")
					return errorNoCommonHash
				}
				c.sessionHash = tiger.New()
				c.cid = newClientID(c.pid, c.sessionHash)

				if len(msg.Params) != 1 {
					c.session.writeLine("HSTA 240")
					return fmt.Errorf("received invalid SID '%s'", msg)
				}
				c.sid = newSessionID(msg.Params[0])
				return nil

			default:
				invalid = append(invalid, msg)
			}
		}
	}
}

func hubIdentifyState(c *client) error {
	//fmt.Println("IDENTIFIY")
	if _, ok := c.inf["NI"]; !ok {
		return errors.New("user nick not specified by INF")
	} else {
		err := c.session.writeLine("BINF %s ID%s PD%s %s", c.sid, c.cid, c.pid, c.inf)
		if err != nil {
			return err
		}
	}
	return nil
}

func hubVerifyState(c *client, invalid []*ReceivedMessage, password string) error {
	//fmt.Println("VERIFY")
	for _, msg := range invalid {
		c.ingress <- msg
	}
	invalid = invalid[:0]
	for {
		select {
		case msg := <-c.ingress:
			switch msg.Command {
			case "STA":
				if msg.Params[0][0] != '0' {
					return fmt.Errorf("%v", msg.Params[1])
				}
				invalid = append(invalid, msg)

			case "GPA":
				if password == "" {
					return errors.New("hub requested a password but none was set")
				}

				nonce, err := base32.StdEncoding.DecodeString(msg.Params[0])
				if err != nil {
					c.session.writeLine("STA 220 Failed\\sto\\sdecode\\snonce:\\s%s", escaper.Replace(err.Error()))
					return err
				}

				c.sessionHash.Reset()
				fmt.Fprint(c.sessionHash, password)
				c.sessionHash.Write(nonce)
				response := base32.StdEncoding.EncodeToString(c.sessionHash.Sum(nil))
				c.session.writeLine("HPAS %s", response)

			case "INF":
				c.processInf(msg)
				if msg.Params[0] == c.SID().String() {
					return nil
				}

			case "QUI":
				var reason string
				for _, field := range msg.Params {
					switch field[:2] {
					case "MS":
						reason = field[2:]
					}
				}
				return fmt.Errorf("kicked by hub: \"%v\"", reason)
			default:
				invalid = append(invalid, msg)
			}
		}
	}
}

func hubNormalState(c *client, invalid []*ReceivedMessage) {
	//fmt.Println("NORMAL")
	for _, msg := range invalid {
		c.ingress <- msg
	}
	select {
	case msg := <-c.ingress:
		switch msg.Command {
		case "GPA", "PAS", "SID":
			c.err <- errors.New("NORMAL is an invalid state for message " + msg.String())
			return
		case "INF":
			c.processInf(msg)
		}

		err := c.processMessage(msg)
		if err != nil {
			c.err <- err
			panic(err.Error())
		}

	case msg := <-c.egress:
		err := c.session.writeLine(msg.Message(c))
		if err != nil {
			c.err <- err
		}
	}
}

func (c *client) processInf(msg *ReceivedMessage) {
	sid := msg.Params[0]
	c.peersMu.Lock()
	p, ok := c.peers[sid]
	if !ok {
		p = newPeer(sid)
		c.peers[sid] = p
	}
	c.peersMu.Unlock()
	p.update(msg.Params[1:])
}

// Ping implements the PING extension; see
// https:///adc.sourceforge.net/ADC-EXT.html#_ping_pinger_extension
func Ping(url *url.URL) (info FieldMap, err error) {
	conn, err := connectToHub(url)
	if err != nil {
		return nil, err
	}

	conn.writeLine("HSUP ADBASE ADTIGR ADPING")
	msg, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	if msg.Command != "SUP" {
		err = errors.New("did not receive SUP: " + msg.String())
		return
	}
	features := make(map[string]bool)

	for _, word := range msg.Params {
		switch word[:2] {
		case "AD":
			features[word[2:]] = true
		default:
			return nil, Error("unknown word in SUP: " + word)
		}
	}
	if !features["PING"] {
		return nil, Error("hub does not support PING")
	}

	info = make(FieldMap)
	for {
		msg, err := conn.ReadMessage()
		if err != nil {
			return nil, err
		}
		if msg.Command == "INF" {
			for _, word := range msg.Params {
				info[word[:2]] = word[2:]
			}
			break
		}
	}
	return
}

/*

// RegisterMessageHandler registers function f with message type c.
// For example, to add a handler for INF messsages, you would use
// h.RegisterMessageHandler("INF", MyINFFunction)
func (h *Hub) RegisterMessageHandler(c string, f func(*Message)) {
	h.handlers[c] = f
}


func (h *Hub) runLoop() {
	for {
		select {
		case msg := <-h.messages:

			f, ok := h.handlers[msg.Command]
			if ok {
				f(msg)
			}

			switch msg.Command {
			case "INF":
				peerSid := msg.Params[0]
				p := h.peers[peerSid]
				if p == nil {
					p = h.newPeer(peerSid)
					h.peers[peerSid] = p
				}
				updatePeer(p, msg)

			case "MSG":
				switch len(msg.Params) {
				case 1:
					h.log.Printf("<hub> %s\n", NewParameterValue(msg.Params[0]))
				case 2:
					p := h.peers[msg.Params[0]]
					h.log.Printf("<%s> %s\n", p.Nick, NewParameterValue(msg.Params[1]))
				}

			case "SCH":
				{
				}

			case "RES":
				if h.sid.String() != msg.Params[1] {
					h.log.Println("the second SID in a DRES message did not match our own")
					continue
				}
				result := new(SearchResult)
				result.peer = h.peers[msg.Params[0]]

				var results chan *SearchResult
				ok := false
				for _, param := range msg.Params[2:] {
					switch param[:2] {
					case "FN":
						result.FullName = param[2:]

					case "SI":
						n, err := fmt.Sscan(param[2:], &result.size)
						if err != nil || n != 1 {
							h.log.Fatalln("error parsing RES SI:", err)
						}

					case "SL":
						n, err := fmt.Sscan(param[2:], &result.peer.Slots)
						if err != nil || n != 1 {
							h.log.Fatalln("error parsing RES SL:", err)
						}

					case "TO":
						results, ok = h.searchResultChans[param[2:]]
					}
				}
				if ok {
					results <- result
				} else {
					h.log.Println("unable to handle RES:", msg.Params)
				}

			case "QUI":
				sid := msg.Params[0]
				h.log.Println("-", h.peers[sid].Nick, "has quit -")
				delete(h.peers, sid)


			case "CTM":
				token := msg.Params[4]
				c, ok := h.rcmChans[token]
				if ok {
					var port uint16
					_, err := fmt.Sscanf(msg.Params[3], "%d", &port)
					if err != nil {
						log.Fatalln("Did not receieve port in CTM message :", err)
					} else {
						c <- port
					}
					//delete(h.rcmChans, t)
					//TODO close the channel
				}

			default:
				h.log.Println("unhandled message: ", msg.Command, msg.Params)
			}

		case r := <-h.searchRequestChan:
			h.searchResultChans[r.token] = r.results
			h.conn.writeLine("BSCH %s TO%s %s TY1", h.sid, r.token, r.Terms)
		}
	}
}


func updatePeer(p *Peer, msg *Message) {
	for _, field := range msg.Params[1:] {
		switch field[:2] {
		case "ID":
			p.CID = field[2:]
		case "I4":
			p.I4 = field[2:]
		case "I6":
			p.I6 = field[2:]
		case "SL":
			fmt.Sscan(field[2:], p.Slots)
		case "NI":
			p.Nick = NewParameterValue(field[2:]).String()
		}
	}
}

func (h *Hub) newPeer(sid string) *Peer {
	return &Peer{
		hub: h,
		SID: sid,
	}
}

func (h *Hub) Close() {
	h.conn.Close()
}
*/
