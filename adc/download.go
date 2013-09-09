// Copyright © 2013 Emery Hemingway
// Released under the terms of the GPL-3

package adc

import (
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"sync"
	"time"
)

type fileChunk struct {
	start uint64
	size  uint64
}

type DownloadConfig struct {
	SearchFilename string
	Hash           *TreeHash
	Verify         bool
	Compress       bool
}

type Download struct {
	search *Search
	dest   io.ReadWriteSeeker

	config     *DownloadConfig
	resultChan chan *SearchResult
	finalChan  chan uint64

	destSeek  uint64
	destSize  uint64
	chunkMu   sync.Mutex
	log       *log.Logger
	doneChans []chan<- error
}

func NewDownload(config *DownloadConfig, logger *log.Logger) (*Download, error) {
	d := &Download{
		config:     config,
		resultChan: make(chan *SearchResult, 32), // buffered to keep from blocking at the hub
		finalChan:  make(chan uint64, 1),
		log:        logger,
	}
	d.chunkMu.Lock()
	return d, nil
}

func (d Download) Done(c chan<- error) {
	if c == nil {
		panic("adc: Download.Done recieved nil channel")
	}
	d.doneChans = append(d.doneChans, c)
}

func (d Download) ResultChannel() chan *SearchResult {
	return d.resultChan
}

func (d *Download) Run(timeout time.Duration) {
	stop := time.After(timeout)

	var result *SearchResult
	if d.config.Hash == nil {
		select {
		case <-stop:
			d.finalChan <- 0
			return
		case result = <-d.resultChan:
			d.destSize = result.Size
			go downloadWorker(d, result)
		}

		go func() {
			for result := range d.resultChan {
				go downloadWorker(d, result)
			}
		}()

	} else {
		for d.destSize == 0 {
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
				d.destSize = result.Size
				go downloadWorker(d, result)
			}
		}

		go func() {
			for result := range d.resultChan {
				if result.Size != d.destSize {
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
	//d.dest, err = os.Create(d.config.OutputFilename)
	if err != nil {
		d.log.Fatalln(err)
	}
	d.chunkMu.Unlock()
}

func (d *Download) getChunk(size uint64) *fileChunk {
	d.chunkMu.Lock()
	//defer d.chunkMu.Unlock()
	fmt.Print("\r", d.destSeek, "/", d.destSize)
	if d.destSeek == d.destSize {
		d.finalChan <- d.destSize
		return nil
	}

	c := new(fileChunk)
	c.start = d.destSeek

	newSeek := d.destSeek + size
	if newSeek > d.destSize {
		c.size = d.destSize - d.destSeek
		d.destSeek = d.destSize
	} else {
		c.size = size
		d.destSeek = newSeek
	}
	return c
}

func downloadWorker(d *Download, r *SearchResult) {
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

		err = p.session.writeLine(f, r.Filename, chunk.start, chunk.size)

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
		switch msg.Command {
		case "STA":
			d.log.Println(msg)
			p.EndSession(sessionId)
			return
		case "SND":
			if msg.Params[0] != "file" || msg.Params[1] != r.Filename {
				p.session.writeLine("CSTA 140 invalid\\sarguments.")
				p.EndSession(sessionId)
				return
			}
			fmt.Sscan(msg.Params[2], &start)
			fmt.Sscan(msg.Params[3], &size)
			if start < chunk.start || size > chunk.size {
				p.session.writeLine("CSTA 140 invalid\\sfile\\srange")
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
					p.session.writeLine("CSTA 140 unknown\\sflags")
					p.EndSession(sessionId)
					return
				}
			default:
				p.session.writeLine("CSTA 140 unknown\\sflags")
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
					p.session.writeLine("CSTA 150 %s", escaper.Replace(err.Error()))
					p.EndSession(sessionId)
					return
				}
				pos += n
			}
		} else {
			for pos < int(size) {
				n, err := p.session.r.Read(buf[pos:])
				if err != nil {
					p.session.writeLine("CSTA 150 %v", escaper.Replace(err.Error()))
					p.EndSession(sessionId)
					return
				}
				pos += n
			}
		}
		p.EndSession(sessionId)

		//n, err := d.dest.WriteAt(buf, int64(start))
		//size = uint64(n)
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

func DownloadByHash(s *Search, destination io.ReadWriteSeeker) (d *Download, err error) {
	d = &Download{
		search: s,
		dest:   destination,
	}

	return
}

type DownloadWorker struct {
	// Compress    int8 // make some compression consts
	peer        *Peer
	filename    string // filename at peer's side
	requestSize int
}

func (d DownloadWorker) get(w io.WriterAt, offset uint64, size int) (n int, err error) {
	sessionId := d.peer.NextSessionId()
	err = d.peer.StartSession(sessionId)
	if err != nil {
		return
	}
	defer d.peer.EndSession(sessionId)

	for n < size {
		if l := size - n; d.requestSize < l {
			d.requestSize = l
		}

		err = d.peer.session.writeLine("CGET file", d.filename, offset, d.requestSize)
		if err != nil {
			return
		}

		var msg *ReceivedMessage
		msg, err = d.peer.session.ReadMessage()
		if err != nil {
			return
		}
		if msg.Command != "SND" {
			err = errors.New(msg.String())
			return
		}

		if msg.Params[0] != "file" || msg.Params[1] != d.filename {
			d.peer.session.writeLine("CSTA 140 expected\\sfile\\s%s", d.filename)
		}

		var o uint64
		o, err = strconv.ParseUint(msg.Params[2], 10, 64)
		if o != offset || err != nil {
			d.peer.session.writeLine("CSTA 140 wanted\\sstart_pos\\s%d,\\snot\\s%s", offset, msg.Params[2])
			err = fmt.Errorf("wanted start_pos %d, not %s", offset, msg.Params[2])
			return
		}
		o, err = strconv.ParseUint(msg.Params[3], 10, 32)
		s := int(o)

		if s < 1 || s > size || err != nil {
			d.peer.session.writeLine("CSTA 140 wanted\\ssize\\sof\\s%d,\\snot\\s%s", size, msg.Params[3])
			err = fmt.Errorf("wanted size of %d, not %s", d.requestSize, msg.Params[3])
			return
		}

		buf := make([]byte, s)
		startOfTransfer := time.Now()

		var pos, l int
		for pos < s {
			l, err = d.peer.session.r.Read(buf[pos:])
			if err != nil {
				l, _ = w.WriteAt(buf[:pos], -1)
				n += l
				return
			}
			pos += l
		}
		duration := time.Since(startOfTransfer)

		l, _ = w.WriteAt(buf, -1)
		size += l
		n += l

		if duration < time.Minute {
			d.requestSize *= 2
		} else if duration > time.Minute*4 {
			d.requestSize /= 2
		}
	}
	return
}
