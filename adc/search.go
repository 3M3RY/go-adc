// Copyright © 2013 Emery Hemingway
// Released under the terms of the GPL-3

package adc

import (
	"strconv"
	"sync"
)

type Search struct {
	mu          sync.RWMutex
	token       string
	terms       FieldMap
	stringTerms FieldSlice
	results     chan *SearchResult
}

type SearchResult struct {
	peer     *Peer
	Filename string
	Size     uint64
	Slots    int
}

func NewSearch() *Search {
	return &Search{
		token:   newToken(),
		terms:   make(FieldMap),
		results: make(chan *SearchResult, 1024),
	}
}

func (s *Search) AddInclude(a string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stringTerms = append(s.stringTerms, "AN"+a)
}

func (s *Search) AddExclude(a string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stringTerms = append(s.stringTerms, "NO"+a)
}

// Add Extension makes sure the extension matches at least one the given extensions;
// extensions must be sent without the leading period ('.').
func (s *Search) AddExtension(a string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stringTerms = append(s.stringTerms, "EX"+a)
}

func (s *Search) AddSmaller(size uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terms["LE"] = strconv.FormatUint(size, 10)
}

func (s *Search) AddLarger(size uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terms["GE"] = strconv.FormatUint(size, 10)
}

func (s *Search) AddExactSize(size uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terms["EQ"] = strconv.FormatUint(size, 10)
}

func (s *Search) MustBeFile() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terms["TY"] = "1"
}

func (s *Search) MustBeDirectory() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terms["TY"] = "2"
}

func (s *Search) AddTTH(tth *TigerTreeHash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terms["TR"] = tth.String()
}

func (s *Search) Send(c *Client) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c.RegisterTokenHandler("RES", s.token, s)
	return c.Session.WriteLine("BSCH %s TO%s", c.sid, s.token, s.terms, s.stringTerms)
}

func (s *Search) Handle(c *Client, m *Message) (err error) {
	r := new(SearchResult)
	for _, word := range m.Params {
		switch word[:2] {
		case "FN": // Full filename including path in share
			r.Filename = word[2:]
		case "SI": // Size, in bytes
			r.Size, err = strconv.ParseUint(word[2:], 10, 64)
			if err != nil {
				return
			}
		case "SL": // Slots currently available
			r.Slots, err = strconv.Atoi(word[2:])
			if err != nil {
				return
			}
		}
	}
	s.results <- r
	return
}

func (s *Search) Results() chan *SearchResult {
	return s.results
}
