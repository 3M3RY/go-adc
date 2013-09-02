package adc

// TODO make STA handler

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"errors"
	"fmt"
	"hash"
	"net"
	"net/url"
	"strings"
)

import "github.com/3M3RY/go-tiger/tiger"
/*
type Hub struct {
	url      *url.URL
	pid      *Identifier
	cid      *Identifier
	sid      *Identifier
	hasher   hash.Hash
	features map[string]bool
	peers    map[string]*Peer
	messages chan *Message
	rcmChans map[string](chan uint16)
	handlers map[string]func(*Message)
}

type HubError struct {
	hub *Hub
	msg string
}

func (e *HubError) Error() string {
	return fmt.Sprintf("%s: %s", e.hub.url, e.msg)
}
*/

var errorKeyprint = errors.New("KEYP verification failed, potential man-in-the-middle attack detected")

// handle initial SUP from the hub
type protocolSUPHandler struct {
	errChan chan error
}

func (h *protocolSUPHandler) Handle(c *Client, m *Message) {
	for _, word := range m.Params {
		switch word[:2] {
		case "AD":
			c.features[word[2:]] = true
		default:
			h.errChan <- errors.New("unknown word " + word + " in SUP")
		}
	}
}

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
func NewHubClient(url *url.URL, pid *Identifier, inf FieldMap) (*Client, error) {
	session, err := connectToHub(url)
	if err != nil {
		return nil, err
	}

	if inf == nil {
		inf = make(FieldMap)
	}
	c := &Client{
		Session: session,
		pid:      pid,
		inf:      inf,
		handlers: make(map[string]ClientMessageHandler),
		features: make(map[string]bool),
	}

	invalidMessages := make(chan *Message, 1024)

	err = hubProtocolState(c, invalidMessages)
	if err != nil {
		return nil, err
	}

	err = hubIdentifyState(c, invalidMessages)
	if err != nil {
		return nil, err
	}

	err = hubVerifyState(c, invalidMessages)
	if err != nil {
		return nil, err
	}

	go hubNormalState(c, invalidMessages)
	return c, nil
}

func hubProtocolState(c *Client, invalid chan *Message) error {
	c.Session.WriteLine("HSUP ADBASE ADTIGR")
	for {
		msg, err := c.Session.ReadMessage()
		if err != nil {
			return err
		}

		switch msg.Cmd {
		case "STA":
			code := msg.Params[0]
			if code[0] != 0 {
				return errors.New(msg.Params[1])
			} else {
				fmt.Println(msg.Params[1])
			}
		case "SUP":
			for _, word := range msg.Params {
				switch word[:2] {
				case "AD":
					c.features[word[2:]] = true
				default:
					return fmt.Errorf("unknown word %s in SUP", word)
				}
			}
		case "SID":
			if !c.features["BASE"] {
				c.Session.WriteLine("HSTA 244 FCBASE")
				return errors.New("Did not receive BASE SUP before SID")
			}
			if !c.features["TIGR"] {
				c.Session.WriteLine("HSTA 247 client\\sonly\\ssupports\\sTGR")
				return errors.New("no common hash function (Tiger)")
			}
			c.SessionHash = tiger.New()
			c.cid = newClientID(c.pid, c.SessionHash)

			if len(msg.Params) != 1 {
				c.Session.WriteLine("HSTA 240")
				return fmt.Errorf("received invalid SID '%s'", msg)
			}
			c.sid = newSessionID(msg.Params[0])
			break

		default:
			invalid <- msg
		}
	}
	return nil
}

func hubIdentifyState(c *Client, invalid chan *Message) error {
	if _, ok := c.inf["NI"]; !ok {
		return errors.New("user nick not specified by INF")
	}
	return c.Session.WriteLine("BINF %s ID%s PD%s", c.sid, c.cid, c.pid, c.inf)
}

func hubVerifyState(c *Client, invalid chan *Message) error {
	for {
		msg, err := c.Session.ReadMessage()
		if err != nil {
			return err
		}

		switch msg.Cmd {
		case "STA":
			code := msg.Params[0]
			if code[0] != 0 {
				return errors.New(msg.Params[1])
			}

		case "GPA":
			//password, ok := c.url.User.Password()
			//if ok == false {
			return errors.New("hub requested a password but none was set")
			//}

			/*
				nonce, _ := base32.StdEncoding.DecodeString(msg.Params[0])

				c.SessionHash.Reset()
				fmt.Fprint(c.SessionHash, password)
				c.SessionHash.Write(nonce)
				response := base32.StdEncoding.EncodeToString(c.SessionHash.Sum(nil))
				h.conn.WriteLine("HPAS %s", response)
			*/

		case "INF":
			if h, ok := c.handlers["INF"]; ok {
				h.Handle(c, msg)
			}
			break

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
			invalid <- msg
		}
	}
	return nil
}

func hubNormalState(c *Client, invalid chan *Message) (err error) {
	for msg := range invalid {
		switch msg.Cmd {
		case "GPA", "PAS", "SID":
			return errors.New("NORMAL is an invalid state for message " + msg.String())
		}

		err = c.processMessage(msg)
		if err != nil {
			return err
		}
	}

	for {
		msg, err := c.Session.ReadMessage()
		switch msg.Cmd {
		case "GPA", "PAS", "SID":
			return errors.New("NORMAL is an invalid state for message " + msg.String())
		}

		err = c.processMessage(msg)
		if err != nil {
			return err
		}
	}
	return nil
}

func Ping(url *url.URL) (info FieldMap, err error) {
	conn, err := connectToHub(url)
	if err != nil {
		return nil, err
	}

	conn.WriteLine("HSUP ADBASE ADTIGR ADPING")
	msg, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	if msg.Cmd != "SUP" {
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
		if msg.Cmd == "INF" {
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

			f, ok := h.handlers[msg.Cmd]
			if ok {
				f(msg)
			}

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
				h.log.Println("unhandled message: ", msg.Cmd, msg.Params)
			}

		case r := <-h.searchRequestChan:
			h.searchResultChans[r.token] = r.results
			h.conn.WriteLine("BSCH %s TO%s %s TY1", h.sid, r.token, r.Terms)
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
