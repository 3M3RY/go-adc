// Copyright 2013 Emery Hemingway.  All rights reserved

package adc

import (
	"fmt"
	"encoding/base32"
	"hash"
	"strings"
)

// An Error represents a numeric error response from a server.
type Status struct {
	str  string
}

func (s *Status) Error() string {
	return s.str
}

func NewStatus(msg *Message) *Status {
	return &Status{fmt.Sprintf("%s %v", msg.Params[0], NewParameterValue(msg.Params[1]))}
}

// A ProtocolError describes a protocol violation such
// as an invalid response or a hung-up connection.
type Error string

func (e Error) Error() string {
	return string(e)
}

// Message represents an ADC protocol message
type Message struct {
	str    string
	Type   byte
	Cmd    string
	Params []string
}

func (m *Message) String() string {
	return m.str
}

// Identifier represents a PID, CID or SID
type Identifier struct {
	raw     []byte
	encoded string
}

func (id *Identifier) String() string { return id.encoded }

// NewPrivateID returns an Identifier for a given seed
func NewPrivateID(d []byte) *Identifier {
	s := base32.StdEncoding.EncodeToString(d)
	s = strings.Split(s, "=")[0]
	return &Identifier{d, s}
}

// NewClientID returns a new Client ID corresponding to a Private ID
func newClientID(pid *Identifier, hash hash.Hash) *Identifier {
	hash.Write(pid.raw)
	raw := hash.Sum(nil)
	s := Base32EncodeString(raw)
	return &Identifier{raw, s}
}

func newSessionID(s string) *Identifier {
	raw, _ := Base32DecodeString(s)
	return &Identifier{raw, s}
}

func Base32DecodeString(s string) (b []byte, err error) {
	b, err = base32.StdEncoding.DecodeString(s)
	return b, err
}

func Base32EncodeString(b []byte) string {
	s := base32.StdEncoding.EncodeToString(b)
	return strings.Split(s, "=")[0]
}

var escaper = strings.NewReplacer(
	" ", "\\s",
	"\n", "\\n",
	"\\", "\\\\")

var deescaper = strings.NewReplacer(
	"\\s", " ",
	"\\n", "\n",
	"\\\\", "\\")

type ParameterValue struct {
	str string
}

func (v *ParameterValue) String() string {
	return v.str
}

func NewParameterValue(s string) *ParameterValue {
	return &ParameterValue{s}
}

func (v *ParameterValue) Format(s fmt.State, c rune) {
	switch c {
	case 's': // Human readable
		fmt.Fprint(s, deescaper.Replace(v.str))

	case 'v': // Space escaped
		fmt.Fprint(s, escaper.Replace(v.str))
	}
}
