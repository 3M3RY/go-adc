// Copyright © 2013 Emery Hemingway
// Released under the terms of the GPL-3

package adc

import (
	"bytes"
	"errors"
	"fmt"
	hashtree "github.com/3M3RY/go-hashtree/hashtree"
	"github.com/3M3RY/go-tiger/tiger"
	"net"
	"sync"
)

type Peer struct {
	client      *Client
	CID         string
	SID         string
	I4          string
	I6          string
	Slots       uint16
	Nick        string
	features    map[string]bool
	session     *Session
	idMu        sync.Mutex
	nextId      uint
	sessionMu   sync.Mutex
	sessionId   uint
	sessionWait map[uint]chan uint
}

// NextSession returns the next id for a communication session.
func (p *Peer) NextSessionId() uint {
	p.idMu.Lock()
	id := p.nextId
	p.nextId++
	p.idMu.Unlock()
	return id
}

// StartSession waits until it is time for the
// session with id to begin.
func (p *Peer) StartSession(id uint) (err error) {
	p.sessionMu.Lock()
	if p.sessionId == id {
		if p.session == nil {
			err = p.connect()
			if err != nil {
				return err
			}
			p.sessionMu.Unlock()
			return err
		} else {
			p.sessionMu.Unlock()
			return nil
		}
	}
	c := make(chan uint)
	if p.sessionWait == nil {
		p.sessionWait = make(map[uint]chan uint)
	}
	p.sessionWait[id] = c
	p.sessionMu.Unlock()
	<-c

	if p.session == nil {
		err = p.connect()
		return
	}
	return
}

// EndSession notifies the Peer that the session with the
// numbered id has completed.
func (p *Peer) EndSession(id uint) {
	p.sessionMu.Lock()
	if p.sessionId != id {
		panic("out of sync")
	}
	id++
	p.sessionId = id
	if p.sessionWait == nil {
		p.sessionWait = make(map[uint]chan uint)
	}
	c, ok := p.sessionWait[id]
	if ok {
		delete(p.sessionWait, id)
	}
	p.sessionMu.Unlock()
	if ok {
		c <- 1
	}
}

type connectToMeHandler struct {
	peer     *Peer
	token    string
	portChan chan string
}

func (h *connectToMeHandler) Handle(c *Client, m *Message) (err error) {
	defer c.UnregisterTokenHandler("CTM", h.token)

	switch m.Cmd {
	case "STA":
		return errors.New(m.String())

	case "CTM":
		if m.Params[0] != PROTOCOL {
			c.Session.WriteLine("DSTA %s %s 142 TO%s PR%s",
				c.sid, h.peer.SID, h.token, PROTOCOL)
			return errors.New("could not accept ConnectToMe, invalid protocol " + m.Params[0])
		}
		h.portChan <- m.Params[1]
		return nil
	}
	return errors.New("CTM handler cannot handle " + m.String())
}

// ReverseConnectToMe sends a RCM message to a Peer.
func (p *Peer) ReverseConnectToMe() (port, token string, err error) {
	token = newToken()

	h := &connectToMeHandler{p, token, make(chan string, 1)}
	p.client.RegisterTokenHandler("CTM", token, h)
	defer p.client.UnregisterTokenHandler("CTM", token)
	// RCM protocol separator token
	err = p.client.Session.WriteLine("DRCM", p.client.sid, p.SID, PROTOCOL, token)
	if err != nil {
		return "", "", err
	}
	port = <-h.portChan
	return
}

func (p *Peer) connect() (err error) {
	if p.features == nil {
		p.features = make(map[string]bool)
	}

	var port, token string
	port, token, err = p.ReverseConnectToMe()

	var conn net.Conn
	if len(p.I4) > 8 {
		conn, err = net.Dial("tcp4", fmt.Sprintf("%s:%d", p.I4, port))
	} else if len(p.I6) > 8 {
		conn, err = net.Dial("tcp6", fmt.Sprintf("[%s]:%d", p.I6, port))
	} else {
		p.client.Session.WriteLine("ISTA 142 TO%s PR%s", token, PROTOCOL)
		return Error("no address information for peer")
	}
	if err != nil {
		p.client.Session.WriteLine("ISTA 142 TO%s PR%s", token, PROTOCOL)
		return err
	}
	p.session = NewSession(conn)

	p.session.WriteLine("CSUP ADBASE ADTIGR ADZLIG")
	msg, err := p.session.ReadMessage()
	if err != nil {
		p.client.Session.WriteLine("ISTA 142 TO%s PR%s", token, PROTOCOL)
		p.session.Close()
		return err
	}

	if err != nil || msg.Cmd != "SUP" {
		p.client.Session.WriteLine("ISTA 142 TO%s PR%s", token, PROTOCOL)
		p.session.Close()
		return Error(msg.String())
	}
	for _, word := range msg.Params {
		switch word[:2] {
		case "AD":
			p.features[word[2:]] = true
		default:
			p.client.Session.WriteLine("ISTA 142 TO%s PR%s", token, PROTOCOL)
			p.session.Close()
			return Error(fmt.Sprintf("unknow word %s in CSUP", word))
		}
	}

	err = p.session.WriteLine("CINF ID%s TO%s", p.client.cid, token)
	if err != nil {
		p.client.Session.WriteLine("ISTA 142 TO%s PR%s", token, PROTOCOL)
		p.session.Close()
		return err
	}

	msg, err = p.session.ReadMessage()
	if err != nil || msg.Cmd != "INF" {
		p.client.Session.WriteLine("ISTA 142 TO%s PR%s", token, PROTOCOL)
		p.session.Close()
		return err
	}
	if msg.Params[0][2:] != p.CID {
		p.client.Session.WriteLine("ISTA 142 TO%s PR%s", token, PROTOCOL)
		p.session.Close()
		return Error("the CID reported by the hub and client do not match")
	}
	return nil
}

// Fetch and verify a row of leaves from Peer
func (p *Peer) getTigerTreeHashLeaves(tth *TigerTreeHash) (leaves [][]byte, err error) {
	if p.session == nil {
		panic("Peer.conn was nil")
	}
	identifier := "TTH/" + tth.String()
	p.session.WriteLine("CGET tthl %s 0 -1", identifier)

	msg, err := p.session.ReadMessage()
	if err != nil {
		return nil, err
	}

	switch msg.Cmd {
	//case "STA":
	//return nil, NewStatus(msg)
	case "SND":
		if msg.Params[0] != "tthl" || msg.Params[1] != identifier || msg.Params[2] != "0" {
			p.session.WriteLine("CSTA 140 Invalid\\sarguments.")
			p.session.Close()
			return nil, Error("received invalid SND" + msg.String())
		}
	default:
		p.session.Close()
		return nil, Error("unhandled message: " + msg.String())
	}

	var tthSize int
	_, err = fmt.Sscanf(msg.Params[3], "%d", &tthSize)
	if err != nil {
		p.session.WriteLine("CSTA 140 Unable\\sto\\sparse\\ssize:\\s" + escaper.Replace(err.Error()))
		p.session.Close()
		return nil, err
	}
	if tthSize < 24 { // hardcoded to the size of tiger
		p.session.WriteLine("CSTA 140 TTH\\sis\\stoo\\ssmall")
		p.session.Close()
		return nil, Error(fmt.Sprintf("received a TTH SND with a size smaller than a single leaf"))
	}

	leafStream := make([]byte, tthSize)

	var pos int
	for pos < tthSize {
		n, err := p.session.r.Read(leafStream[pos:])
		if err != nil {
			p.session.Close()
			return nil, err
		}
		pos += n
	}

	tree := hashtree.New(tiger.New())

	leafCount := tthSize / 24 // hardcoded to tiger
	leaves = make([][]byte, leafCount)
	i := 0
	j := 24 // hardcoded to tiger
	k := 0
	for k < leafCount {
		leaf := leafStream[i:j]
		tree.Write(leaf)
		leaves[k] = leaf
		i = j
		j += 24
		k++
	}
	treeRoot := tree.Sum(nil)

	if !bytes.Equal(treeRoot, tth.raw) {
		return nil, Error("leaves failed verification")
	}

	return
}
