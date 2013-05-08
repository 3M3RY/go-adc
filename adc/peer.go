// Copyright (c) 2013 Emery Hemingway
package adc

import (
	"bytes"
	"crypto/rand"
	"fmt"
)

import "code.google.com/p/go-tiger/tiger"
import "code.google.com/p/go-hashtree/tree"

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

// Fetch and verify a row of leaves from a client Conn
func (p *Peer) getTigerTreeHashLeaves(conn *Conn, tth *TigerTreeHash) (leaves [][]byte, err error) {

	tthParam := "TTH/" + tth.String()
	conn.WriteLine("CGET tthl %s 0 -1", tthParam)
	
	msg, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	switch msg.Cmd {
	case "STA":
		return nil, NewStatus(msg)
	case "SND":
		if msg.Params[0] != "tthl" || msg.Params[1] != tthParam || msg.Params[2] != "0" {
			conn.WriteLine("CSTA 140 Invalid\\sarguments.")
			conn.Close()
			return nil, Error("received invalid SND" + msg.String())
		}
	default:
		conn.Close()
		return nil, Error("unhandled message: " + msg.String())
	}

	var tthSize int
	_, err = fmt.Sscanf(msg.Params[3], "%d", &tthSize)
	if err != nil {
		conn.WriteLine("CSTA 140 Unable\\sto\\sparse\\ssize:\\s", NewParameterValue(err.Error()))
		conn.Close()
		return nil, err
	}
	if tthSize < 24 { // hardcoded to the size of tiger
		conn.WriteLine("CSTA 140 TTH\\sis\\stoo\\ssmall")
		conn.Close()
		return nil, Error(fmt.Sprintf("received a TTH SND with a size smaller than a single leaf"))
	}
	
	
	leafStream := make([]byte, tthSize)

	var pos int
	for pos < tthSize {
		n, err := conn.R.Read(leafStream[pos:])
		if err != nil {
			conn.Close()
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
