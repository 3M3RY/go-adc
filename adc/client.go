// Copyright © 2013 Emery Hemingway
// Released under the terms of the GPL-3

package adc

import (
	//"errors"
	"hash"
	"sync"
)

// Client is the interface to an ADC client.
type Client interface {
	PID() *Identifier
	CID() *Identifier
	SID() *Identifier
	Send(m Messager) error
	RegisterHandler(action string, h ClientMessageHandler)
	RegisterTokenHandler(action, token string, h ClientMessageHandler)
	UnregisterHandler(action string)
	UnregisterTokenHandler(action, token string)
	Peer(SID string) *Peer
}

type client struct {
	pid           *Identifier
	cid           *Identifier
	sid           *Identifier
	session       *Session
	idMu          sync.Mutex
	nextId        uint
	sessionMu     sync.Mutex
	sessionId     uint
	sessionWait   map[uint]chan uint
	sessionHash   hash.Hash // hash interface to session hash function, see https://adc.sourceforge.net/ADC.html#_session_hash
	inf           FieldMap
	handlersMu    sync.RWMutex
	handlers      map[string]ClientMessageHandler
	tokenHandlers map[string]map[string]ClientMessageHandler
	features      map[string]bool
	egress        chan Messager
	ingress       chan *ReceivedMessage
	err           chan error
	peersMu       sync.RWMutex
	peers         map[string]*Peer
}

func (c *client) PID() *Identifier { return c.pid }
func (c *client) CID() *Identifier { return c.cid }
func (c *client) SID() *Identifier { return c.sid }

// ClientMessageHandler is the interface of an object that can handle messages
type ClientMessageHandler interface {
	Handle(c Client, m *ReceivedMessage) error
}

// ClientMessageTokenHandler is the interface of an object that can handle messages
// with a reference token.
//type ClientMessageTokenHandler interface {
//	Handle(c *Client, m *Message) error
//}

func (c *client) processMessage(m *ReceivedMessage) (err error) {
	c.handlersMu.RLock()
	defer c.handlersMu.RUnlock()
	if hm, ok := c.tokenHandlers[m.Command]; ok {
		for _, w := range m.Params {
			if w[:2] == "TO" {
				if h, ok := hm[w[2:]]; ok {
					return h.Handle(c, m)
				} else {
					panic("token not found")
					break
				}
			}
		}

		if h, ok := c.handlers[m.Command]; ok {
			err = h.Handle(c, m)
		}
	}
	return
}

// NextSessionId returns the next id for a communication session.
func (c *client) NextSessionId() uint {
	c.idMu.Lock()
	id := c.nextId
	c.nextId++
	c.idMu.Unlock()
	return id
}

// StartSession waits until it is time for the
// session with id to begin.
func (c *client) StartSession(id uint) (err error) {
	c.sessionMu.Lock()
	if c.sessionId == id {
		c.sessionMu.Unlock()
		return
	}
	ch := make(chan uint)
	if c.sessionWait == nil {
		c.sessionWait = make(map[uint]chan uint)
	}
	c.sessionWait[id] = ch
	c.sessionMu.Unlock()
	<-ch
	return
}

// EndSession notifies the Peer that the session with the
// numbered id has completed.
func (c *client) EndSession(id uint) {
	c.sessionMu.Lock()
	if c.sessionId != id {
		panic("out of sync")
	}
	id++
	c.sessionId = id
	if c.sessionWait == nil {
		c.sessionWait = make(map[uint]chan uint)
	}
	ch, ok := c.sessionWait[id]
	if ok {
		delete(c.sessionWait, id)
	}
	c.sessionMu.Unlock()
	if ok {
		ch <- 1
	}
}

func (c *client) RegisterHandler(action string, h ClientMessageHandler) {
	c.handlersMu.Lock()
	defer c.handlersMu.Unlock()
	c.handlers[action] = h
}

func (c *client) RegisterTokenHandler(action, token string, h ClientMessageHandler) {
	c.handlersMu.Lock()
	defer c.handlersMu.Unlock()
	m, ok := c.tokenHandlers[action]
	if !ok {
		m = make(map[string]ClientMessageHandler)
		c.tokenHandlers[action] = m
	}
	m[token] = h
}

func (c *client) UnregisterHandler(action string) {
	delete(c.handlers, action)
}

func (c *client) UnregisterTokenHandler(action, token string) {
	delete(c.tokenHandlers[action], token)
}

func (c *client) Send(m Messager) (err error) {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	c.egress <- m
	// BUG(emery): no error handling defined
	return
}

func (c *client) Peer(SID string) *Peer {
	c.peersMu.RLock()
	defer c.peersMu.RUnlock()
	return c.peers[SID]
}
