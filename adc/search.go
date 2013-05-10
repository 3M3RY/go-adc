package adc

import "sync"

type Search struct {
	info map[string]string
}

type SearchRequest struct {
	tth     string
	results chan *SearchResult
}

type SearchResult struct {
	peer     *Peer
	filename string
	size     uint64
	index    int
}

// A peerQueue implements heap.Interface and 
// queues Peer objects by slots.
type SearchResultQueue struct {
	results []*SearchResult
	mu      sync.Mutex
}

func newSearchResultQueue() *SearchResultQueue {
	q := new(SearchResultQueue)
	q.results = make([]*SearchResult, 0)
	return q
}

func (q SearchResultQueue) Len() int { return len(q.results) }

func (q SearchResultQueue) Less(i, j int) bool { 
	return q.results[i].peer.Slots > q.results[j].peer.Slots 
}

func (q SearchResultQueue) Swap(i, j int) {
	q.mu.Lock()
	q.results[i], q.results[j] = q.results[j], q.results[i]
	q.results[i].index = i
	q.results[j].index = j
	q.mu.Unlock()
}

func (q *SearchResultQueue) Push(x interface{}) {
	q.mu.Lock()
	n := len(q.results)
	q.results = q.results[0 : n+1]
	r := x.(*SearchResult)
	r.index = n
	q.results[n] = r
	q.mu.Unlock()
}

func (q *SearchResultQueue) Pop() interface{} {
	q.mu.Lock()
	n := len(q.results)
	r := q.results[n]
	q.results = q.results[:n-1]
	r.index = -1
	q.mu.Unlock()
	return r
}
