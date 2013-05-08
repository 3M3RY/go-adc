// Copyright (c) 2013 Emery Hemingway
package adc

import (
	"fmt"
	"os"
	"container/ring"
)

type fileChunk struct {
	digest []byte
	seek uint64
	size int
}

type DownloadDispatcher struct {
	// Maybe the dispatcher should collect the searh results 
	// so that it knows how many peers there are available.
	// If it knows how many peers there are, it can adjust 
	// chuck size and determine how much to what level it should 
	// request TTH leaves.
	tth           *TigerTreeHash
	searchResults chan *SearchResult
	chunks        *ring.Ring
	file          *os.File
}

func NewDownloadDispatcher(tth *TigerTreeHash, filename string) (*DownloadDispatcher, error) {
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

	var leaves [][]byte
	for {
		conn, err := r.hub.PeerConn(r.peer)
		if err != nil {
			fmt.Println("Error: could not connect to peer for hash tree: ", err)
			return
		}

		leaves, err = r.peer.getTigerTreeHashLeaves(conn, d.tth)
		if err == nil {
			break
		}
	}
		

	var fileSize uint64
	fmt.Println(r.fields)
	_, err := fmt.Sscanf(r.fields["SI"], "%d", &fileSize)
	if err != nil {
		panic(err)
	}
	fmt.Println("file size is: ", fileSize)
	
	leafCount := len(leaves)
	d.chunks = ring.New(leafCount)

	chunkSize := fileSize / uint64(leafCount)
	var p uint64
	var i int
	fmt.Println(len(leaves))
	for i := 0; i < leafCount; i++ {
		chunk := d.chunks.Next()
		chunk.Value = &fileChunk{leaves[i], p, int(chunkSize)}
		p += chunkSize
	}
	chunk := d.chunks.Next()
	chunk.Value = &fileChunk{leaves[i], p, int(fileSize - p)}
		
	fmt.Print(d.chunks.Len(), " chunks ", chunkSize, " long ")

	// if a chunk is bigger than 65536, break the chunk down into 32768 sized pieces
	// if there are two many chunks and not enough leaves, request more leaves
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
