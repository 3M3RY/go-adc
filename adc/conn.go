// Copyright (c) 2013 Emery Hemingway
package adc

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
)

var (
	MessageTypeB = byte('B') // Broadcast
	MessageTypeC = byte('C') // Client message
	MessageTypeD = byte('D') // Direct message
	MessageTypeE = byte('E') // Echo message
	MessageTypeF = byte('F') // Feature broadcast
	MessageTypeH = byte('H') // Hub message
	MessageTypeI = byte('I') // Info message
	MessageTypeU = byte('U') // UDP message
)

// A Conn represents a ADC protocol connection.
// It consists of a Reader and Writer to manage I/O.
// These embedded types carry methods with them;
// see the documentation of those types for details.
type Conn struct {
	Reader
	Writer
	conn io.ReadWriteCloser
}

// NewConn returns a new Conn using conn for I/O.
func NewConn(conn io.ReadWriteCloser) *Conn {
	return &Conn{
		Reader: Reader{R: bufio.NewReader(conn)},
		Writer: Writer{W: bufio.NewWriter(conn)},
		conn:   conn,
	}
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

// Dial connects to the give address on the given network using net.Dial
// and then returns a new Conn for the connection.
func Dial(network, addr string) (*Conn, error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return NewConn(c), nil
}

func (c *Conn) ReadMessage() (*Message, error) {
	s, err := c.ReadLine()
	if err != nil {
		return nil, err
	}
	t := s[0]
	words := strings.Fields(s[1:])
	m := &Message{t, words[0], words[1:]}
	return m, nil
}

var eom = []byte{'\n'}

func (c *Conn) WriteLine(format string, a ...interface{}) error {
	fmt.Fprintf(c.W, format, a...)
	c.W.Write(eom)
	return c.W.Flush()
}

type Reader struct {
	R *bufio.Reader
}

// NewReader returns a new Reader reading from r.
func NewReader(r *bufio.Reader) *Reader {
	return &Reader{R: r}
}

// ReadLine reads a single line from r,
// eliding the final \n from the return string.
func (r *Reader) ReadLine() (string, error) {
	line, err := r.readLineSlice()
	messageType := line[0]
	switch messageType {
	case MessageTypeB: // Broadcast
		{
		}
	case MessageTypeC: // Client message
		{
		}
	case MessageTypeD: // Direct message
		{
		}
	case MessageTypeE: // Echo message
		{
		}
	case MessageTypeF: // Feature broadcast
		{
		}
	case MessageTypeH: // Hub message
		{
		}
	case MessageTypeI: // Info message
		{
		}
	case MessageTypeU: // UDP message
		{
		}
	default:
		// TODO make this error non-fatal
		panic(fmt.Sprintf("bad message type %c", messageType))
	}

	return string(line), err
}

func (r *Reader) readLineSlice() ([]byte, error) {
	var line []byte
	for {
		l, more, err := r.R.ReadLine()
		if err != nil {
			return nil, err
		}
		// Avoid the copy if the first call produced a full line.
		if line == nil && !more {
			return l, nil
		}
		line = append(line, l...)
		if !more {
			break
		}
	}
	return line, nil
}

// A writer implements convience methods for writing
// messages to a ADC protocol connection.
type Writer struct {
	W *bufio.Writer
}

// NewWriter returns a new Writer writing to w.
func NewWriter(w *bufio.Writer) *Writer {
	return &Writer{W: w}
}
