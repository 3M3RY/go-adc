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

func NewSearch() *SearchRequest {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return &SearchRequest{
		token: fmt.Sprintf("%X", b),
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

func (s *SearchRequest) SetResultChannel(c chan *SearchResult) {
	s.results = c
}