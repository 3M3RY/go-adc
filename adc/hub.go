// Copyright (c) 2013 Emery Hemingway
package adc

import (
	"encoding/base32"
	"fmt"
	"hash"
	"log"
	"net/url"
	"time"
)

import "code.google.com/p/go-tiger/tiger"

// States
const (
	PROTOCOL = iota
	IDENTIFY
	VERIFY
	NORMAL
	DATA
)

type Hub struct {
	url               *url.URL
	pid               *Identifier
	cid               *Identifier
	sid               *Identifier
	conn              *Conn
	hasher            hash.Hash
	features          map[string]bool
	info              map[string]string
	wait              time.Duration
	log               log.Logger
	peers             map[string]*Peer
	messages          chan *Message
	searchRequestChan chan *SearchRequest
	searchResultChans map[string](chan *SearchResult)
	rcmChans          map[string](chan uint16)
}

type HubError struct {
	hub *Hub
	msg string
}

func (e *HubError) Error() string {
	return fmt.Sprintf("%s: %s", e.hub.url, e.msg)
}

type UrlError struct {
	url *url.URL
	msg string
}

func (e *UrlError) Error() string {
	return fmt.Sprintf("%s: %s", e.url, e.msg)
}

func NewHub(hubUrl string, pid *Identifier) (*Hub, error) {
	u, err := url.Parse(hubUrl)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "adc":
		{
		}
	case "adcs":
		return nil, &UrlError{u, "TLS ecryption is not supported"}
	default:
		return nil, &UrlError{u, "unrecognized URL format"}
	}

	hub := &Hub{
		url:  u,
		pid:  pid,
		wait: time.Second * 8,
	}

	return hub, nil
}

// Connect and authenticate to the hub
func (h *Hub) Open() (err error) {
	h.conn, err = Dial("tcp", h.url.Host)
	if err != nil {
		return
	}
	h.messages = make(chan *Message)
	h.features = make(map[string]bool)
	h.info = make(map[string]string)
	h.peers = make(map[string]*Peer)
	h.searchRequestChan = make(chan *SearchRequest, 32)
	h.searchResultChans = make(map[string](chan *SearchResult))

	go func() {
		for {
			// block here for incoming messages
			msg, err := h.conn.ReadMessage()
			if err != nil {
				log.Fatal("error parsing reply: ", err)
			}
			// fmt.Println(message)
			h.messages <- msg
		}
	}()

	//// PROTOCOL ////
	h.conn.WriteLine("HSUP ADBASE ADTIGR")

	// Get SUP from hub
	msg := <-h.messages

	if msg.Cmd != "SUP" {
		s := "did not recieve SUP: "
		for _, word := range msg.Params {
			s = s + " " + word
		}
		return ProtocolError(s)
	}

	for _, word := range msg.Params {
		switch word[:2] {
		case "AD":
			h.features[word[2:]] = true
		default:
			log.Println("Error, unknow word %s in reply", word)
		}
	}

	if h.features["TIGR"] {
		h.hasher = tiger.New()
		h.cid = newClientID(h.pid, h.hasher)
	} else {
		h.conn.Close()
		return ProtocolError("no common hash function")
	}

	// Get SID from hub
	msg = <-h.messages
	if msg.Cmd != "SID" {
		h.conn.Close()
		return ProtocolError("did not receive SID assignment from hub")
	}
	h.sid = newSessionID(msg.Params[0])

	//// IDENTIFIY ////
	var nick string
	if h.url.User != nil {
		nick = h.url.User.Username()
	} else {
		nick = "adc.go"
	}

	h.conn.WriteLine("BINF %s ID%s PD%s SS0 SF0 APadcget VE0.0 SL0 NI%v CT64",
		h.sid, h.cid, h.pid, NewParameterValue(nick))

	for {
		msg := <-h.messages
		switch msg.Cmd {

		case "GPA":
			//// VERIFY ////
			password, ok := h.url.User.Password()
			if ok == false {
				h.conn.Close()
				return ProtocolError("hub requested a password but none was set")
			}

			nonce, _ := base32.StdEncoding.DecodeString(msg.Params[0])

			h.hasher.Reset()
			fmt.Fprint(h.hasher, password)
			h.hasher.Write(nonce)
			response := base32.StdEncoding.EncodeToString(h.hasher.Sum(nil))
			h.conn.WriteLine("HPAS %s", response)

		case "INF":
			//// NORMAL ////
			sid := msg.Params[0]
			p := h.newPeer(sid)
			h.peers[sid] = p
			for _, field := range msg.Params[1:] {
				p.info[field[:2]] = field[2:]
			}

			if sid == h.sid.String() {
				go h.runLoop()
				return nil
			}

		case "STA":
			code, _ := fmt.Sscan("%d", msg.Params[0])
			if code == 0 {
				fmt.Printf("%s\n", msg.Params[1])
			} else {
				return &Error{code, msg.Params[1]}
			}

		default:
			s := "unknown message recieved before INF list :"
			for _, word := range msg.Params {
				s = s + " " + word
			}
			return ProtocolError(s)
		}
	}
	return nil
}

func (h *Hub) runLoop() {
	for {
		select {
		case msg := <-h.messages:
			switch msg.Cmd {
			case "INF":
				peerSid := msg.Params[0]
				p := h.peers[peerSid]
				if p == nil {
					p = h.newPeer(peerSid)
					h.peers[peerSid] = p
				}
				for _, word := range msg.Params[1:] {
					p.info[word[:2]] = word[2:]
				}
				//fmt.Printf("Updating %s: %v\n", p.info["NI"], p.info)

			case "MSG":
				switch len(msg.Params) {
				case 1:
					fmt.Printf("<hub> %s\n", NewParameterValue(msg.Params[0]))
				case 2:
					p := h.peers[msg.Params[0]]
					fmt.Printf("<%s> %s\n", p.info["NI"], NewParameterValue(msg.Params[1]))
				}

			case "SCH":
				{
				}

			case "RES":
				if h.sid.String() != msg.Params[1] {
					panic("the second SID in a DRES message did not match our own")
				}
				peer := h.peers[msg.Params[0]]
				fields := make(map[string]string)
				for _, word := range msg.Params[2:] {
					fields[word[:2]] = word[2:]
				}
				result := &SearchResult{h, peer, fields}
				tth, ok := fields["TR"]
				if ok {
					h.searchResultChans[tth] <- result
				}

			case "QUI":
				fmt.Println(h.peers[msg.Params[0]].info["NI"], "has quit")
				//delete(h.peers, msg.Params[0])

			case "STA":
				// TODO handle STA better
				code, err := fmt.Sscan("%d", msg.Params[0])
				if err != nil {
					panic(err)
				}
				fmt.Printf("(status-%.3d) %s\n", code, NewParameterValue(msg.Params[1]))

			case "CTM":
				t := msg.Params[4]
				c, ok := h.rcmChans[t]
				if ok {
					p, err := fmt.Sscan("%d", msg.Params[3])
					if err == nil {
						c <- uint16(p)
					}
					delete(h.rcmChans, t)
					//TODO close the channel
				}

			default:
				fmt.Println("unhandled message type ", msg.Cmd)
				fmt.Println(msg.Params)
			}

		case r := <-h.searchRequestChan:
			h.searchResultChans[r.tth] = r.result
			h.conn.WriteLine("BSCH %s TR%s", h.sid, r.tth)
		}
	}
}

func (h *Hub) newPeer(sid string) *Peer {
	return &Peer{
		sid:  sid,
		hub:  h,
		info: make(map[string]string),
	}
}

// ReverseConnectToMe sends a RCM message to a Peer with token string.
// A channel is returned that will carry the the port number in the 
// CTM response. Be sure to use a fresh token, or will nothing will 
// be coming back down that channel
func (h *Hub) ReverseConnectToMe(p *Peer, token string) chan uint16 {
	// RCM protocol separator token
	c := make(chan uint16)
	h.rcmChans[token] = c
	h.conn.WriteLine("DRCM %s %s ADC/1.0 %X", h.sid, p.sid, token)
	return c
}

func (h *Hub) SearchByTTR(tth string, result chan *SearchResult) {
	r := &SearchRequest{
		tth:    tth,
		result: result,
	}
	h.searchRequestChan <- r
}

func (h *Hub) Close() {
	h.conn.Close()
}

type Search struct {
	info map[string]string
}

type SearchRequest struct {
	tth    string
	result chan *SearchResult
}

type SearchResult struct {
	hub    *Hub
	peer   *Peer
	fields map[string]string
}