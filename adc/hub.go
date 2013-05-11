package adc

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"fmt"
	"hash"
	"log"
	"net"
	"net/url"
	"strings"
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
	info              map[string]*ParameterValue
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

func NewHub(hubUrl string) (*Hub, error) {
	u, err := url.Parse(hubUrl)
	if err != nil {
		return nil, err
	}

	hub := &Hub{
		url:      u,
		features: make(map[string]bool),
		info:     make(map[string]*ParameterValue),
	}

	return hub, nil
}

// Connect and authenticate to the hub
func (h *Hub) Open(pid *Identifier) (err error) {
	var digest hash.Hash
	var keyPrint []byte
	q := h.url.Query()
	v, ok := q["kp"]
	if ok {
		params := strings.Split(v[0], "/")
		switch params[0] {
		case "SHA256":
			digest = sha256.New()
			keyPrint, err = base32.StdEncoding.DecodeString(params[1] + "====")
			if err != nil {
				return err
			}
		default:
			return Error(params[0] + " KEYP verification is not supported")
		}
	}

	switch h.url.Scheme {
	case "adc":
		if digest != nil {
			return Error("KEYP specified but adcs:// was not")
		}
		c, err := net.Dial("tcp", h.url.Host)
		if err != nil {
			return err
		}
		h.conn = NewConn(c)


	case "adcs":
		c, err := tls.Dial("tcp", h.url.Host, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err
		}
		if digest != nil {
			digest.Write(c.ConnectionState().PeerCertificates[0].Raw)
			if !bytes.Equal(digest.Sum(nil), keyPrint) {
				return Error("KEYP verification failed, potential man-in-the-middle attack detected")
			}
		}		
		h.conn = NewConn(c)
		
	default:
		return &UrlError{h.url, "unrecognized URL format"}
	}


	h.pid = pid
	h.messages = make(chan *Message)
	h.peers = make(map[string]*Peer)
	h.searchRequestChan = make(chan *SearchRequest, 32)
	h.searchResultChans = make(map[string](chan *SearchResult))
	h.rcmChans = make(map[string](chan uint16))

	go func() {
		for {
			// block here for incoming messages
			msg, err := h.conn.ReadMessage()
			if err != nil {
				log.Fatal("error parsing reply: ", err)
			}
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
		return Error(s)
	}

	for _, word := range msg.Params {
		switch word[:2] {
		case "AD":
			h.features[word[2:]] = true
		default:
			log.Println("Error, unknown word %s in SUP", word)
		}
	}

	if h.features["TIGR"] {
		h.hasher = tiger.New()
		h.cid = newClientID(h.pid, h.hasher)
	} else {
		h.conn.Close()
		return Error("no common hash function")
	}

	// Get SID from hub
	msg = <-h.messages
	if msg.Cmd != "SID" {
		h.conn.Close()
		return Error("did not receive SID assignment from hub")
	}
	h.sid = newSessionID(msg.Params[0])

	//// IDENTIFIY ////
	var nick string
	if h.url.User != nil {
		nick = h.url.User.Username()
	} else {
		nick = "go-adc"
	}

	h.conn.WriteLine("BINF %s ID%s PD%s SS0 SF0 APadcget VE0.0 SL0 NI%v",
		h.sid, h.cid, h.pid, NewParameterValue(nick))

	for {
		msg := <-h.messages
		switch msg.Cmd {

		case "GPA":
			//// VERIFY ////
			password, ok := h.url.User.Password()
			if ok == false {
				h.conn.Close()
				return Error("hub requested a password but none was set")
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
			if sid == h.sid.String() {
				go h.runLoop()
				return nil
			}
			p := h.newPeer(sid)
			h.peers[sid] = p
			updatePeer(p, msg)

		case "STA":
			code, _ := fmt.Sscan("%d", msg.Params[0])
			if code == 0 {
				fmt.Printf("%s\n", msg.Params[1])
			} else {
				return NewStatus(msg)
			}

		case "QUI":
			var reason string
			for _, field := range msg.Params {
				switch field[:2] {
				case "MS":
					reason = field[2:]
				}
			}
			return Error(fmt.Sprintf("kicked by hub: \"%s\"", NewParameterValue(reason)))

		case "MSG":
			fmt.Printf("<hub> %s\n", NewParameterValue(msg.Params[0]))

		default:
			s := "unknown message recieved before INF list : " + msg.Cmd
			for _, word := range msg.Params {
				s = s + " " + word
			}
			return Error(s)
		}
	}
	return nil
}

func (h *Hub) Ping() (info map[string]*ParameterValue, err error) {
	if h.conn != nil {
		if h.features["PING"] {
			return h.info, nil
		} else {
			return nil, Error("hub does not support PING")

		}
	}

	c, err := net.Dial("tcp", h.url.Host)
	if err != nil {
		return nil, err
	}
	conn := NewConn(c)
	defer conn.Close()

	conn.WriteLine("HSUP ADBASE ADTIGR ADPING")
	msg, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	if msg.Cmd != "SUP" {
		return nil, Error("did not receive SUP: " + msg.String())
	}

	for _, word := range msg.Params {
		switch word[:2] {
		case "AD":
			h.features[word[2:]] = true
		default:
			return nil, Error("unknown word in SUP: " + word)
		}
	}
	if !h.features["PING"] {
		return nil, Error("hub does not support PING")
	}
	for {
		msg, err := conn.ReadMessage()
		if err != nil {
			return nil, err
		}
		if msg.Cmd == "INF" {
			info = make(map[string]*ParameterValue)
			for _, word := range msg.Params {
				info[word[:2]] = NewParameterValue(word[2:])
			}
			return info, nil
		}
	}
	return nil, nil
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
				updatePeer(p, msg)

			case "MSG":
				switch len(msg.Params) {
				case 1:
					fmt.Printf("<hub> %s\n", NewParameterValue(msg.Params[0]))
				case 2:
					p := h.peers[msg.Params[0]]
					fmt.Printf("<%s> %s\n", p.Nick, NewParameterValue(msg.Params[1]))
				}

			case "SCH":
				{
				}

			case "RES":
				if h.sid.String() != msg.Params[1] {
					panic("the second SID in a DRES message did not match our own")
				}
				result := new(SearchResult)
				result.peer = h.peers[msg.Params[0]]

				var results chan *SearchResult
				ok := true
				for _, param := range msg.Params[2:] {
					switch param[:2] {
					case "FN":
						result.filename = param[2:]
					case "SI":
						n, err := fmt.Sscan(param[2:], &result.size)
						if err != nil || n != 1 {
							fmt.Println("error parsing RES SI:", err)
							ok = false

						}
					case "SL":
						n, err := fmt.Sscan(param[2:], &result.peer.Slots)
						if err != nil || n != 1 {
							fmt.Println("error parsing RES SL:", err)
							ok = false
						}
					case "TR":
						results, ok = h.searchResultChans[param[2:]]
					}
				}
				if ok {
					results <- result
				}

			case "QUI":
				sid := msg.Params[0]
				fmt.Println("-", h.peers[sid].Nick, "has quit -")
				delete(h.peers, sid)

			case "STA":
				// TODO handle STA better
				fmt.Println(msg)
				/*
					var code uint8
					_, err := fmt.Sscan(msg.Params[0], &code)
					if err != nil {
						panic(err.Error())
					}
					fmt.Printf("(status-%.3d) %s\n", code, NewParameterValue(msg.Params[1]))
				*/

			case "CTM":
				token := msg.Params[4]
				c, ok := h.rcmChans[token]
				if ok {
					var port uint16
					_, err := fmt.Sscanf(msg.Params[3], "%d", &port)
					if err != nil {
						fmt.Println("Did not receieve port in CTM message :", err)
					} else {
						c <- port
					}
					//delete(h.rcmChans, t)
					//TODO close the channel
				}

			default:
				fmt.Println("unhandled message type ", msg.Cmd)
				fmt.Println(msg.Params)
			}

		case r := <-h.searchRequestChan:
			h.searchResultChans[r.tth] = r.results
			h.conn.WriteLine("BSCH %s TR%s", h.sid, r.tth)
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

// ReverseConnectToMe sends a RCM message to a Peer with token string.
// A channel is returned that will carry the the port number in the 
// CTM response. Be sure to use a fresh token, or will nothing will 
// be coming back down that channel
func (h *Hub) ReverseConnectToMe(p *Peer, token string) chan uint16 {
	// RCM protocol separator token
	c := make(chan uint16)
	h.rcmChans[token] = c
	h.conn.WriteLine("DRCM %s %s ADC/1.0 %s", h.sid, p.SID, token)
	return c
}

func (h *Hub) SearchByTTR(tth string, results chan *SearchResult) {
	r := &SearchRequest{
		tth:     tth,
		results: results,
	}
	h.searchRequestChan <- r
}

func (h *Hub) Close() {
	h.conn.Close()
}
