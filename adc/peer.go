// Copyright 2013 Emery Hemingway.  All rights reserved

package adc

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
)

import "code.google.com/p/go-tiger/tiger"
import "code.google.com/p/go-hashtree/tree"

type Peer struct {
	hub         *Hub
	CID         string
	SID         string
	I4          string
	I6          string
	Slots       uint16
	Nick        string
	features    map[string]bool
	conn        *Conn
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
func (p *Peer) StartSession(id uint) error {
	p.sessionMu.Lock()
	if p.sessionId == id {
		if p.conn == nil {
			p.sessionMu.Unlock()
			return p.connect()
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
	
	if p.conn == nil {
		return p.connect()
	}
	return nil
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

func (p *Peer) connect() (err error) {
	if p.features == nil {
		p.features = make(map[string]bool)
	}

	b := make([]byte, 4)
	_, err = rand.Read(b)
	if err != nil {
		return err
	}
	token := fmt.Sprintf("%X", b)

	portChan := p.hub.ReverseConnectToMe(p, token)
	port := <-portChan

	var c net.Conn
	if len(p.I4) > 8 {
		c, err = net.Dial("tcp4", fmt.Sprintf("%s:%d", p.I4, port))
	} else if len(p.I6) > 8 {
		c, err = net.Dial("tcp6", fmt.Sprintf("[%s]:%d", p.I6, port))
	} else {
		p.hub.conn.WriteLine("ISTA 142 TO%s PRADC/1.0", token)
		return Error("no address information for peer")
	}
	if err != nil {
		p.hub.conn.WriteLine("ISTA 142 TO%s PRADC/1.0", token)
		return err
	}
	p.conn = NewConn(c)

	p.conn.WriteLine("CSUP ADBASE ADTIGR")
	msg, err := p.conn.ReadMessage()
	if err != nil {
		p.hub.conn.WriteLine("ISTA 142 TO%s PRADC/1.0", token)
		p.conn.Close()
		return err
	}

	if err != nil || msg.Cmd != "SUP" {
		p.hub.conn.WriteLine("ISTA 142 TO%s PRADC/1.0", token)
		p.conn.Close()
		return Error(msg.String())
	}
	for _, word := range msg.Params {
		switch word[:2] {
		case "AD":
			p.features[word[2:]] = true
		default:
			p.hub.conn.WriteLine("ISTA 142 TO%s PRADC/1.0", token)
			p.conn.Close()
			return Error(fmt.Sprintf("unknow word %s in CSUP", word))
		}
	}

	err = p.conn.WriteLine("CINF ID%s TO%s", p.hub.cid, token)
	if err != nil {
		p.hub.conn.WriteLine("ISTA 142 TO%s PRADC/1.0", token)
		p.conn.Close()
		return err
	}

	msg, err = p.conn.ReadMessage()
	if err != nil || msg.Cmd != "INF" {
		p.hub.conn.WriteLine("ISTA 142 TO%s PRADC/1.0", token)
		p.conn.Close()
		return err
	}
	if msg.Params[0][2:] != p.CID {
		p.hub.conn.WriteLine("ISTA 142 TO%s PRADC/1.0", token)
		p.conn.Close()
		return Error("the CID reported by the hub and client do not match")
	}
	return nil
}

// Fetch and verify a row of leaves from a client P.Conn
func (p *Peer) getTigerTreeHashLeaves(tth *TigerTreeHash) (leaves [][]byte, err error) {
	if p.conn == nil {
		panic("Peer.conn was nil")
	}
	identifier := "TTH/" + tth.String()
	p.conn.WriteLine("CGET tthl %s 0 -1", identifier)

	msg, err := p.conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	switch msg.Cmd {
	case "STA":
		return nil, NewStatus(msg)
	case "SND":
		if msg.Params[0] != "tthl" || msg.Params[1] != identifier || msg.Params[2] != "0" {
			p.conn.WriteLine("CSTA 140 Invalid\\sarguments.")
			p.conn.Close()
			return nil, Error("received invalid SND" + msg.String())
		}
	default:
		p.conn.Close()
		return nil, Error("unhandled message: " + msg.String())
	}

	var tthSize int
	_, err = fmt.Sscanf(msg.Params[3], "%d", &tthSize)
	if err != nil {
		p.conn.WriteLine("CSTA 140 Unable\\sto\\sparse\\ssize:\\s", NewParameterValue(err.Error()))
		p.conn.Close()
		return nil, err
	}
	if tthSize < 24 { // hardcoded to the size of tiger
		p.conn.WriteLine("CSTA 140 TTH\\sis\\stoo\\ssmall")
		p.conn.Close()
		return nil, Error(fmt.Sprintf("received a TTH SND with a size smaller than a single leaf"))
	}

	leafStream := make([]byte, tthSize)

	var pos int
	for pos < tthSize {
		n, err := p.conn.R.Read(leafStream[pos:])
		if err != nil {
			p.conn.Close()
			return nil, err
		}
		pos += n
	}

	tree := tree.New(tiger.New())

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

type sequencer struct {
	mu   sync.Mutex
	id   uint
	wait map[uint]chan uint
}
