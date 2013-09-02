// Copyright © 2013 Emery Hemingway
// Released under the terms of the GPL-3

package adc

import (
	"hash"
)

type Client struct {
	Session       *Session
	SessionHash   hash.Hash // hash interface to session hash function, see https://adc.sourceforge.net/ADC.html#_session_hash
	pid           *Identifier
	cid           *Identifier
	sid           *Identifier
	inf           FieldMap
	handlers      map[string]ClientMessageHandler
	tokenHandlers map[string]map[string]ClientMessageHandler
	features      map[string]bool
}

// ClientMessageHandler is the interface of an object that can handle messages
type ClientMessageHandler interface {
	Handle(c *Client, m *Message) error
}

// ClientMessageTokenHandler is the interface of an object that can handle messages
// with a reference token.
//type ClientMessageTokenHandler interface {
//	Handle(c *Client, m *Message) error
//}

func (c *Client) processMessage(m *Message) (err error) {
	if th, ok := c.tokenHandlers[m.Cmd]; ok {
		for _, w := range m.Params {
			if w[2:] == "TO" {
				if h, ok := th[w[:2]]; ok {
					return h.Handle(c, m)
				} else {
					break
				}
			}
		}

		if h, ok := c.handlers[m.Cmd]; ok {
			err = h.Handle(c, m)
		}
	}
	return
}

func (c *Client) RegisterHandler(action string, h ClientMessageHandler) {
	c.handlers[action] = h
}

func (c *Client) RegisterTokenHandler(action, token string, h ClientMessageHandler) {
	c.tokenHandlers[action][token] = h
}

func (c *Client) UnRegisterHandler(action string) {
	delete(c.handlers, action)
}

func (c *Client) UnregisterTokenHandler(action, token string) {
	delete(c.tokenHandlers[action], token)
}
