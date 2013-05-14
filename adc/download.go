package adc

import (
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

type FilenameDownloadDispatcher struct {
	searchName     string
	resultChan     chan *SearchResult
	finalChan      chan uint64
	filename       string
	file           *os.File
	fileSeek       uint64
	fileSize       uint64
	chunkMu        sync.Mutex
	log            *log.Logger
}

func NewFilenameDownloadDispatcher(searchName, filename string, logger *log.Logger) (*FilenameDownloadDispatcher, error) {
	d := &FilenameDownloadDispatcher{
		searchName: searchName,
		resultChan: make(chan *SearchResult, 32), // buffered to keep from blocking at the hub
		finalChan:  make(chan uint64),
		filename:   filename,
		log:        logger,
	}
	d.chunkMu.Lock()
	return d, nil
}


func (d *FilenameDownloadDispatcher) ResultChannel() chan *SearchResult {
	return d.resultChan
}

func (d *FilenameDownloadDispatcher) FinalChannel() chan uint64 {
	return d.finalChan
}

func (d *FilenameDownloadDispatcher) Run() {
	fmt.Println("got here")
	var result *SearchResult

	// I should check the file sizes on results coming in

	result = <- d.resultChan
	fmt.Println("got here")
	d.fileSize = result.size
	go nameDownloadWorker(d, result)

	go func() {
		for result := range d.resultChan {
			go nameDownloadWorker(d, result)
		}
	}()

	var err error
	d.file, err = os.Create(d.filename)
	if err != nil {
		d.log.Fatalln(err)
	}
	d.chunkMu.Unlock()
}

func (d *FilenameDownloadDispatcher) getChunk(size uint64) *fileChunk {
	d.chunkMu.Lock()
	defer d.chunkMu.Unlock()
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

func nameDownloadWorker(d *FilenameDownloadDispatcher, r *SearchResult) {
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
		err = p.conn.WriteLine("CGET file %s %d %d", r.FullName, chunk.start, chunk.size)
		if err != nil {
			return
		}

		msg, err := p.conn.ReadMessage()
		if err != nil {
			return
		}
		var start uint64
		var size uint64

		switch msg.Cmd {
		case "STA":
			d.log.Println(msg)
			return
		case "SND":
			if msg.Params[0] != "file" || msg.Params[1] != r.FullName {
				p.conn.WriteLine("CSTA 140 invalid\\sarguments.")
				return
			}
			fmt.Sscan(msg.Params[2], &start)
			fmt.Sscan(msg.Params[3], &size)
			if start < chunk.start || size > chunk.size {
				p.conn.WriteLine("CSTA 140 invalid\\sfile\\srange")
				return
			}

		default:
			return
		}
		buf := make([]byte, size)
		var pos int

		startOfTransfer := time.Now()
		for pos < int(size) {
			n, err := p.conn.R.Read(buf[pos:])
			if err != nil {
				p.conn.WriteLine("CSTA 150 %v", NewParameterValue(err.Error()))
				return
			}
			pos += n
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


type TTHDownloadDispatcher struct {
	tth            *TigerTreeHash
	resultChan     chan *SearchResult
	finalChan      chan uint64
	filename       string
	file           *os.File
	fileSeek       uint64
	fileSize       uint64
	chunkMu        sync.Mutex
	log            *log.Logger
}

func NewTTHDownloadDispatcher(tth *TigerTreeHash, fileName string, logger *log.Logger) (*TTHDownloadDispatcher, error) {
	d := &TTHDownloadDispatcher{
		tth:        tth ,
		resultChan: make(chan *SearchResult, 32), // buffered to keep from blocking at the hub
		finalChan:  make(chan uint64),
		filename:   fileName,
		log:        logger,
	}
	d.chunkMu.Lock()
	return d, nil
}

func (d *TTHDownloadDispatcher) ResultChannel() chan *SearchResult {
	return d.resultChan
}

func (d *TTHDownloadDispatcher) FinalChannel() chan uint64 {
	return d.finalChan
}

func (d *TTHDownloadDispatcher) Run() {
	var result *SearchResult

	// I should check the file sizes on results coming in

	for result = range d.resultChan {
		peer := result.peer
		sessionId := peer.NextSessionId()
		err := peer.StartSession(sessionId)
		if err != nil {
			fmt.Printf("Error: could not connect to %s for hash tree:\n", peer.Nick, err)
			continue
		}

		_, err = peer.getTigerTreeHashLeaves(d.tth)
		peer.EndSession(sessionId)
		if err != nil {
			fmt.Printf("Error: could not get leaves from %v: %v\n", peer.Nick, err)
			continue
		} else {
			d.fileSize = result.size
			go tthDownloadWorker(d, result)
			break
		}
	}

	go func() {
		for result := range d.resultChan {
			if result.size != d.fileSize {
				_, err := result.peer.getTigerTreeHashLeaves(d.tth)
				if err != nil {
					fmt.Printf("Error: could not get leaves from %v: %v\n", result.peer.Nick, err)
					continue
				} else {
					panic("two hosts presented valid hash tree leaves but different file sizes")
				}
			}
			go tthDownloadWorker(d, result)
		}
	}()

	var err error
	d.file, err = os.Create(d.filename)
	if err != nil {
		d.log.Fatalln(err)
	}
	d.chunkMu.Unlock()
}

func (d *TTHDownloadDispatcher) getChunk(size uint64) *fileChunk {
	d.chunkMu.Lock()
	defer d.chunkMu.Unlock()
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

func tthDownloadWorker(d *TTHDownloadDispatcher, r *SearchResult) {
	p := r.peer
	identifier := "TTH/" + d.tth.String()
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
		err = p.conn.WriteLine("CGET file %s %d %d", identifier, chunk.start, chunk.size)
		if err != nil {
			return
		}

		msg, err := p.conn.ReadMessage()
		if err != nil {
			return
		}
		var start uint64
		var size uint64

		switch msg.Cmd {
		case "STA":
			d.log.Println(msg)
			return
		case "SND":
			if msg.Params[0] != "file" || msg.Params[1] != identifier {
				p.conn.WriteLine("CSTA 140 invalid\\sarguments.")
				return
			}
			fmt.Sscan(msg.Params[2], &start)
			fmt.Sscan(msg.Params[3], &size)
			if start < chunk.start || size > chunk.size {
				p.conn.WriteLine("CSTA 140 invalid\\sfile\\srange")
				return
			}

		default:
			return
		}
		buf := make([]byte, size)
		var pos int

		startOfTransfer := time.Now()
		for pos < int(size) {
			n, err := p.conn.R.Read(buf[pos:])
			if err != nil {
				p.conn.WriteLine("CSTA 150 %v", NewParameterValue(err.Error()))
				return
			}
			pos += n
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
