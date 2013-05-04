package adc

import (
	"fmt"
	"os"
)

type chunk struct {
	seek uint64
	size uint
}

type DownloadDispatcher struct {
	// Maybe the dispatcher should collect the searh results 
	// so that it knows how many peers there are available.
	// If it knows how many peers there are, it can adjust 
	// chuck size and determine how much to what level it should 
	// request TTH leaves.
	tth           string
	searchResults chan *SearchResult
	chunks        chan chunk
	file          *os.File
}

func NewDownloadDispatcher(tth, filename string) (*DownloadDispatcher, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	d := &DownloadDispatcher{
		tth:           tth,
		searchResults: make(chan *SearchResult, 256),
		file:          file,
	}
	return d, nil
}

func (d *DownloadDispatcher) Run() {
	defer d.file.Close()
	r := <-d.searchResults

	conn, err := r.hub.PeerConn(r.peer)
	if err != nil {
		fmt.Println("Error: could not connect to peer for hash tree: ", err)
		return
	}
	defer conn.Close()
	
	// Get the full hash tree
	tthField := fmt.Sprintf("TTH/%s", d.tth)
	conn.WriteLine("CGET tthl %s 0 -1", tthField)

	msg, err := conn.ReadMessage()
	if err != nil {
		fmt.Println(err)
		return
	}
	switch msg.Cmd {
	case "STA":
		fmt.Println(msg)
		return
	case "SND":
		if msg.Params[0] != "tthl" || msg.Params[1] != tthField || msg.Params[2] != "0" {
			conn.WriteLine("CSTA 140 Invalid\\sarguments")
			return
		}
	default:
		fmt.Println("unhandled message: ", msg)
		return
	}

	fmt.Println(msg)

	var tthSize int
	_, err = fmt.Sscanf(msg.Params[3], "%d", &tthSize)
	if err != nil {
		fmt.Println(err)
		conn.WriteLine("CSTA 140 Error\\sparsing\\ssize: %v", NewParameterValue(err.Error()))
		return
	}
	if tthSize < 0 {
		conn.WriteLine("CSTA 140 Invalid\\sTTH\\ssize")
		return
	}
	
	b := make([]byte, tthSize)
	
	var pos int
	for pos < tthSize {
		n, err := conn.R.Read(b[pos:])
		if err != nil {
			fmt.Println(err)
			return
		}
		pos += n
	}
	
	_, err = d.file.Write(b)
	if err != nil {
		fmt.Println(err)
	}

}

func (d *DownloadDispatcher) ResultChannel() chan *SearchResult {
	return d.searchResults
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