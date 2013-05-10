package adc

import (
	"fmt"
	"os"
)

type fileChunk struct {
	start uint64
	size  uint64
}

type DownloadDispatcher struct {
	// Maybe the dispatcher should collect the searh results 
	// so that it knows how many peers there are available.
	// If it knows how many peers there are, it can adjust 
	// chuck size and determine how much to what level it should 
	// request TTH leaves.
	tth            *TigerTreeHash
	resultChan     chan *SearchResult
	results        int
	pendingChunks  chan *fileChunk
	finishedChunks chan *fileChunk
	chunks         []*fileChunk
	filename       string
	file           *os.File
}

func NewDownloadDispatcher(tth *TigerTreeHash, filename string) (*DownloadDispatcher, error) {
	d := &DownloadDispatcher{
		tth:        tth,
		resultChan: make(chan *SearchResult, 32), //buffered for safety
		filename:   filename,
	}
	return d, nil
}

func (d *DownloadDispatcher) Run() {
	var leaves [][]byte
	var fileSize uint64
	var result *SearchResult

	for result = range d.resultChan {
		peer := result.peer
		sessionId := peer.NextSessionId()
		err := peer.StartSession(sessionId)
		if err != nil {
			fmt.Printf("Error: could not connect to %s for hash tree:\n", peer.Nick, err)
			continue
		}

		leaves, err = peer.getTigerTreeHashLeaves(d.tth)
		peer.EndSession(sessionId)
		if err != nil {
			fmt.Printf("Error: could not get leaves from %v: %v\n", peer.Nick, err)
			continue
		} else {
			fileSize = result.size
			break
		}
	}

	/*
	go func() {
		for result := range d.resultChan {
			go downloadWorker(d, result)
			d.results++
		}
	}()
	*/

	fmt.Println("file size is: ", fileSize)
	fmt.Println("leaf count is:", len(leaves))

	d.pendingChunks = make(chan *fileChunk)
	d.finishedChunks = make(chan *fileChunk)
	go downloadWorker(d, result)
	d.results++

	chunkSize := fileSize / uint64(d.results*2)

	var err error
	d.file, err = os.Create(d.filename)
	if err != nil {
		fmt.Println(err)
	}

	var start uint64
	end := chunkSize
	for start < fileSize {
		d.pendingChunks <- &fileChunk{start, end}
		start += chunkSize
		end += chunkSize
	}
}

func (d *DownloadDispatcher) ResultChannel() chan *SearchResult {
	return d.resultChan
}

func downloadWorker(d *DownloadDispatcher, r *SearchResult) {
	identifier := "TTH/" + d.tth.String()
	var start uint64
	var size uint64
	
	peer := r.peer

	for chunk := range d.pendingChunks {
		sessionId := peer.NextSessionId()
		err := peer.StartSession(sessionId)
		if err != nil {
			fmt.Println("could not open session with %v: %s", peer.Nick, err)
			return
		}
		err = peer.conn.WriteLine("CGET file %s %d %d", identifier, chunk.start, chunk.size)
		if err != nil {
			d.pendingChunks <- chunk
			return
		}

		msg, err := peer.conn.ReadMessage()
		if err != nil {
			d.pendingChunks <- chunk
			return
		}
		
		switch msg.Cmd {
		case "STA":
			fmt.Println(msg)
			d.pendingChunks <- chunk
			return
		case "SND":
			if msg.Params[0] != "file" || msg.Params[1] != identifier {
				peer.conn.WriteLine("CSTA 140 invalid\\sarguments.")
				fmt.Println("sending a chunk back to d.pendingChunks because of", msg.Params)
				d.pendingChunks <- chunk
				return
			}
			fmt.Sscan(msg.Params[2], &start)
			fmt.Sscan(msg.Params[3], &size)
			if start < chunk.start || size > chunk.size {
				peer.conn.WriteLine("CSTA 140 invalid\\sfile\\srange")
				fmt.Println("sending a chunk back to d.pendingChunks because of", msg.Params)
				d.pendingChunks <- chunk
				return
			}

		default:
			fmt.Println("sending a chunk back to d.pendingChunks because of", msg.Params)
			d.pendingChunks <- chunk
			return
		}
		buf := make([]byte, size)
		var pos int
		for pos < int(size) {
			n, err := peer.conn.R.Read(buf[pos:])
			fmt.Println("Wrote", n, "bytes from Peer.conn")
			if err != nil {
				d.pendingChunks <- chunk
				peer.conn.WriteLine("CSTA 150 %v", NewParameterValue(err.Error()))
				return
			}
			pos += n
		}
		peer.EndSession(sessionId)

		n, err := d.file.WriteAt(buf, int64(start))
		fmt.Println("Wrote", n, "bytes to file")
		size = uint64(n)
		if err != nil {
			fmt.Println("sending a chunk back to d.pendingChunks because of", err)
			d.pendingChunks <- &fileChunk{start + size, chunk.size - size}
		}
		
		//d.finishedChunks <- &fileChunk{start, size}
		fmt.Println("finished a worker run")
	}
}

/*
func DownloadChunksFromPeer(p Peer, peerFilename, tree chan hashLeaf, chunks chan chunk) {
	conn, err := hub

	err = p.Open()
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer p.conn.Close()

	for chunk := range chunks {
		// GET type identifier start_pos bytes
		p.conn.WriteLine("CGET file %s %d %d", peerFilename, chunk.seek, chunk.size)

		msg, err := p.conn.ReadMessage()
		if err != nil {
			fmt.Println(err)
			return nil
		}
		var sndSeek int
		var sndSize int
		switch msg.Cmd {
		case "SND":
			// SND type identifier start_pos bytes
			if msg.Params[0] != "file" {
				// TODO return an error
				fmt.Println("SND response had a type other than file: ", msg.Params[0])
				return nil
			}
			if msg.Params[1] != peerFilename {
				fmt.Println("SND response had a filename other than what was requested: ", msg.Params[1])
				// TODO return an error
				return nil
			}
			sndSeek, err = fmt.Sscan("%d", msg.Params[2])
			if err != nil {
				fmt.Println(err)
				return err
			}
			sndSize, err = fmt.Sscan("%d", msg.Params[3])
			if err != nil {
				fmt.Println(err)
				return err
			}
		default:
			return nil
		}

		// read from the client
		buf := make([]byte, sndSize, sndSize)
		n, err := p.conn.Read(buf)
		if err != nil {
			chunks <- chunk
		}

	}


	for leaf := range tree {




		hash.Write(chunk.buf)
		if hash.Sum(nil) == leaf.digest {
			chunks <- chunk
		}

	}
}

func writeToFile(filename string, chunks chan chunk, errChan chan error) {
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		errChan <- err
		return
	}

	for chunk := range chunks {
		_, err := file.WriteAt(chunk.buffer, chunk.position)
		if err != nil {
			errChan <- err
			return
		}
	}
}
*/
