// Copyright 2013 Emery Hemingway.  All rights reserved

package adc

import (
	"encoding/base32"
	"fmt"
	"hash"
	"math/rand"
	"strings"
	"time"
	"strconv"
)

var PROTOCOL = "ADC/1.0"


func init() {
	rand.Seed(time.Now().UnixNano())
}

func newToken() string {
	return strconv.FormatUint(uint64(rand.Uint32()), 36)
}


/*
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
*/

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
	s := base32EncodeString(raw)
	return &Identifier{raw, s}
}

func newSessionID(s string) *Identifier {
	raw, _ := base32DecodeString(s)
	return &Identifier{raw, s}
}

func base32DecodeString(s string) (b []byte, err error) {
	return base32.StdEncoding.DecodeString(s)
}

func base32EncodeString(b []byte) string {
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

// FieldMap is a map type for ADC message fields
type FieldMap map[string]string

func (f FieldMap) Format(s fmt.State, c rune) {
	switch c {
	case 'v': // Human readable
		for k, v := range f {
			fmt.Fprint(s, k+deescaper.Replace(v))
		}

	case 's': // Space escaped
		for k, v := range f {
			fmt.Fprint(s, k+escaper.Replace(v))
		}
	}
}

// FieldSlice is a slice type for ADC message fields
type FieldSlice []string

func (f FieldSlice) Format(s fmt.State, c rune) {
	switch c {
	case 'v': // Human readable
		for _, w := range f {
			fmt.Fprint(s, deescaper.Replace(w))
		}

	case 's': // Space escaped
		for _, w := range f {
			fmt.Fprint(s, escaper.Replace(w))
		}
	}
}

//func (m Inf) String() (s string) {
//	for k, v := range(m) {
//		s = append(s, fmt.Sprintf(" %s%s", escaper.Replace(v)))
//	}
//	return
//}
