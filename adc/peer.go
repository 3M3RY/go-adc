// Copyright (c) 2013 Emery Hemingway
package adc

import (
	"crypto/rand"
	"fmt"
)

type Peer struct {
	hub      *Hub
	sid      string
	features map[string]bool
	info     map[string]string
}

func (p *Peer) Open() (err error) {
	b := make([]byte, 3)
	_, err = rand.Read(b)
	if err != nil {
		return err
	}

	t := fmt.Sprintf("%X", b)

	c := p.hub.ReverseConnectToMe(p, t)
	port := <-c
	fmt.Println(port)
	return nil

}
