// Copyright © 2013 Emery Hemingway
// Released under the terms of the GPL-3

package adc

import (
	"encoding/base32"
)

type TreeHash struct {
	raw    []byte
	cooked string
}

func (t *TreeHash) String() string {
	return t.cooked
}

func NewTreeHash(s string) (*TreeHash, error) {
	b, err := base32.StdEncoding.DecodeString(s + "=")
	if err != nil {
		return nil, err
	}
	return &TreeHash{b, s}, nil
}

//func NewTreeHashFromBytes(b []byte) *TreeHash {
//	return &TreeHash{b, base32.StdEncoding.EncodeToString(b)}
//}
