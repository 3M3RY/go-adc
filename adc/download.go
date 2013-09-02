// Copyright © 2013 Emery Hemingway
// Released under the terms of the GPL-3

package adc

import (
	"compress/zlib"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

type fileChunk struct {
	start uint64
	size  uint64
}

type DownloadConfig struct {
	OutputFilename string
	SearchFilename string
	Hash           *TigerTreeHash
	Verify         bool
	Compress       bool
}

type DownloadDispatcher struct {
	config     *DownloadConfig
	resultChan chan *SearchResult
	finalChan  chan uint64
	file       *os.File
	fileSeek   uint64
	fileSize   uint64
	chunkMu    sync.Mutex
	log        *log.Logger
}

func NewDownloadDispatcher(config *DownloadConfig, logger *log.Logger) (*DownloadDispatcher, error) {
	d := &DownloadDispatcher{
		config:     config,
		resultChan: make(chan *SearchResult, 32), // buffered to keep from blocking at the hub
		finalChan:  make(chan uint64, 1),
		log:        logger,
	}
	d.chunkMu.Lock()
	return d, nil
}

func (d DownloadDispatcher) ResultChannel() chan *SearchResult {
	return d.resultChan
}

func (d *DownloadDispatcher) FinalChannel() chan uint64 {
	return d.finalChan
}

func (d *DownloadDispatcher) Run(timeout time.Duration) {
	stop := time.After(timeout)

	var result *SearchResult
	if d.config.Hash == nil {
		select {
		case <-stop:
			d.finalChan <- 0
			return
		case result = <-d.resultChan:
			d.fileSize = result.Size
			go downloadWorker(d, result)
		}

		go func() {
			for result := range d.resultChan {
				go downloadWorker(d, result)
			}
		}()

	} else {
		for d.fileSize == 0 {
			select {
			case <-stop:
				d.finalChan <- 0
				return

			case result = <-d.resultChan:
				peer := result.peer
				sessionId := peer.NextSessionId()
				err := peer.StartSession(sessionId)
				if err != nil {
					fmt.Printf("Error: could not connect to %v for hash tree:\n", peer.Nick, err)
					continue
				}

				_, err = peer.getTigerTreeHashLeaves(d.config.Hash)
				peer.EndSession(sessionId)
				if err != nil {
					fmt.Printf("Error: could not get leaves from %v: %v\n", peer.Nick, err)
					continue
				}
				d.fileSize = result.Size
				go downloadWorker(d, result)
			}
		}

		go func() {
			for result := range d.resultChan {
				if result.Size != d.fileSize {
					_, err := result.peer.getTigerTreeHashLeaves(d.config.Hash)
					if err != nil {
						fmt.Printf("Error: could not get leaves from %v: %v\n", result.peer.Nick, err)
						continue
					} else {
						panic("two hosts presented valid hash tree leaves but different file sizes")
					}
				}
				go downloadWorker(d, result)
			}
		}()
	}

	var err error
	d.file, err = os.Create(d.config.OutputFilename)
	if err != nil {
		d.log.Fatalln(err)
	}
	d.chunkMu.Unlock()
}

func (d *DownloadDispatcher) getChunk(size uint64) *fileChunk {
	d.chunkMu.Lock()
	//defer d.chunkMu.Unlock()
	fmt.Print("\r", d.fileSeek, "/", d.fileSize)
	if d.fileSeek == d.fileSize {
		d.finalChan <- d.fileSize
		return nil
	}

	c := new(fileChunk)
	c.start = d.fileSeek

	newSeek := d.fileSeek + size
	if newSeek > d.fileSize {
		c.size = d.fileSize - d.fileSeek
		d.fileSeek = d.fileSize
	} else {
		c.size = size
		d.fileSeek = newSeek
	}
	return c
}

func downloadWorker(d *DownloadDispatcher, r *SearchResult) {
	p := r.peer
	requestSize := uint64(65536)
	for {
		chunk := d.getChunk(requestSize)
		if chunk == nil {
			break
		}

		sessionId := p.NextSessionId()
		err := p.StartSession(sessionId)
		if err != nil {
			d.log.Println("could not open session with %v: %s", p.Nick, err)
			return
		}

		var f string
		if p.features["ZLIG"] && d.config.Compress {
			f = "CGET file %s %d %d ZL1"
		} else {
			f = "CGET file %s %d %d"
		}

		err = p.session.WriteLine(f, r.Filename, chunk.start, chunk.size)

		if err != nil {
			p.EndSession(sessionId)
			return
		}

		msg, err := p.session.ReadMessage()
		if err != nil {
			p.EndSession(sessionId)
			return
		}
		var start uint64
		var size uint64

		var zl bool
		switch msg.Cmd {
		case "STA":
			d.log.Println(msg)
			p.EndSession(sessionId)
			return
		case "SND":
			if msg.Params[0] != "file" || msg.Params[1] != r.Filename {
				p.session.WriteLine("CSTA 140 invalid\\sarguments.")
				p.EndSession(sessionId)
				return
			}
			fmt.Sscan(msg.Params[2], &start)
			fmt.Sscan(msg.Params[3], &size)
			if start < chunk.start || size > chunk.size {
				p.session.WriteLine("CSTA 140 invalid\\sfile\\srange")
				p.EndSession(sessionId)
				return
			}
			switch len(msg.Params) {
			case 4:
			case 5:
				switch msg.Params[4] {
				case "ZL0":
				case "ZL1":
					zl = true
				default:
					p.session.WriteLine("CSTA 140 unknown\\sflags")
					p.EndSession(sessionId)
					return
				}
			default:
				p.session.WriteLine("CSTA 140 unknown\\sflags")
				p.EndSession(sessionId)
				return

			}
		default:
			p.EndSession(sessionId)
			return
		}
		buf := make([]byte, size)
		var pos int

		startOfTransfer := time.Now()
		if zl {
			r, err := zlib.NewReader(p.session.r)
			if err != nil {
				p.EndSession(sessionId)
				return
			}

			for pos < int(size) {
				n, err := r.Read(buf[pos:])
				if err != nil {
					p.session.WriteLine("CSTA 150 %s", escaper.Replace(err.Error()))
					p.EndSession(sessionId)
					return
				}
				pos += n
			}
		} else {
			for pos < int(size) {
				n, err := p.session.r.Read(buf[pos:])
				if err != nil {
					p.session.WriteLine("CSTA 150 %v", escaper.Replace(err.Error()))
					p.EndSession(sessionId)
					return
				}
				pos += n
			}
		}
		p.EndSession(sessionId)

		n, err := d.file.WriteAt(buf, int64(start))
		size = uint64(n)
		if err != nil {
			return
		}

		// a logarithmic increase seems like a good idea,
		// we want peers on a LAN to blow away the others
		duration := time.Since(startOfTransfer)
		if duration < time.Minute {
			requestSize *= 2
		} else if duration > time.Minute*4 {
			requestSize /= 2
		}
	}
}
