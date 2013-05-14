package adc

import (
	"crypto/rand"
	"fmt"
)

type Search struct {
	info map[string]string
}

type SearchResult struct {
	peer     *Peer
	FullName string
	size     uint64
}

type SearchRequest struct {
	Terms string
	token string
	results chan *SearchResult
}

func NewSearch(c chan *SearchResult) *SearchRequest {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return &SearchRequest{
		token: fmt.Sprintf("%x", b),
		results: c,
	}
}

func (s *SearchRequest) AddTTH(tth *TigerTreeHash) {
	s.Terms = s.Terms + " TR" + tth.String()
}

func (s *SearchRequest) AddInclude(a string) {
	s.Terms = s.Terms + " AN" + a
}

func (s *SearchRequest) AddExclude(a string) {
	s.Terms = s.Terms + " NO" + a
}
