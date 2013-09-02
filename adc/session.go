// Copyright © 2013 Emery Hemingway
// Released under the terms of the GPL-3

package adc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	messageTypeB = byte('B') // Broadcast
	messageTypeC = byte('C') // Client message
	messageTypeD = byte('D') // Direct message
	messageTypeE = byte('E') // Echo message
	messageTypeF = byte('F') // Feature broadcast
	messageTypeH = byte('H') // Hub message
	messageTypeI = byte('I') // Info message
	messageTypeU = byte('U') // UDP message
)

// A Session represents a ADC protocol connection.
type Session struct {
	// SID *Identifier
	r    *bufio.Reader
	w    *bufio.Writer
	conn io.ReadWriteCloser
}

// NewSession returns a new ADC session using conn for I/O.
func NewSession(rwc io.ReadWriteCloser) *Session {
	return &Session{
		r:    bufio.NewReader(rwc),
		w:    bufio.NewWriter(rwc),
		conn: rwc,
	}
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	return s.conn.Close()
}

func (s *Session) ReadMessage() (*Message, error) {
	l, err := s.readLine()
	if err != nil {
		return nil, err
	}
	t := l[0]
	words := strings.Fields(l[1:])
	m := &Message{l, t, words[0], words[1:]}
	return m, nil
}

var eom = []byte{'\n'}

// WriteLine may be used to write ADC protocol messages to a Session connection.
// Omit the trailing newline.
func (s *Session) WriteLine(format string, a ...interface{}) error {
	fmt.Fprintf(s.w, format, a...)
	s.w.Write(eom)
	return s.w.Flush()
}

// readLine reads a single line from r,
// eliding the final \n from the return string.
func (s *Session) readLine() (string, error) {
	line, err := s.r.ReadString(0x0a)
	if err != nil {
		return "", err
	}
	messageType := line[0]
	switch messageType {
	case messageTypeB: // Broadcast
		{
		}
	case messageTypeC: // Client message
		{
		}
	case messageTypeD: // Direct message
		{
		}
	case messageTypeE: // Echo message
		{
		}
	case messageTypeF: // Feature broadcast
		{
		}
	case messageTypeH: // Hub message
		{
		}
	case messageTypeI: // Info message
		{
		}
	case messageTypeU: // UDP message
		{
		}
	default:
		// TODO make this error non-fatal
		return "", errors.New(fmt.Sprintf("bad message type %c for message %s", messageType, line))
	}

	return string(line), err
}
