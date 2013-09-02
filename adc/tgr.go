// Copyright © 2013 Emery Hemingway
// Released under the terms of the GPL-3

package adc

import (
	"encoding/base32"
)

type TigerTreeHash struct {
	raw    []byte
	cooked string
}

func (t *TigerTreeHash) String() string {
	return t.cooked
}

func NewTigerTreeHash(s string) (*TigerTreeHash, error) {
	b, err := base32.StdEncoding.DecodeString(s + "=")
	if err != nil {
		return nil, err
	}
	return &TigerTreeHash{b, s}, nil
}

func NewTigerTreeHashFromBytes(b []byte) *TigerTreeHash {
	return &TigerTreeHash{b, base32.StdEncoding.EncodeToString(b)}
}
