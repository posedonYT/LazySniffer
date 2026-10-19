package pktgen

// TCPConv builds a TCP connection with correct sequence numbers.
type TCPConv struct {
	Flow Flow
	TS   int64
	Step int64 // time between packets
	MSS  int
	seq  [2]uint32
	Pkts []Packet
}

// NewTCPConv starts a connection at ts with a handshake.
func NewTCPConv(f Flow, ts int64) *TCPConv {
	c := &TCPConv{Flow: f, TS: ts, Step: 1e6, MSS: 1400, seq: [2]uint32{1000, 50000}}
	c.add(0, SYN, nil)
	c.seq[0]++
	c.add(1, SYN|ACK, nil)
	c.seq[1]++
	c.add(0, ACK, nil)
	return c
}

func (c *TCPConv) flow(dir int) Flow {
	if dir == 0 {
		return c.Flow
	}
	return c.Flow.Rev()
}

func (c *TCPConv) add(dir int, flags byte, data []byte) {
	c.TS += c.Step
	ack := c.seq[1-dir]
	opts := []byte(nil)
	if flags&SYN != 0 {
		opts = SynOpts(1460, 7)
	}
	if flags&SYN != 0 && flags&ACK == 0 {
		ack = 0
	}
	c.Pkts = append(c.Pkts, Packet{TS: c.TS, Data: TCP(c.flow(dir), c.seq[dir], ack, flags, 1024, opts, data)})
}

// Send transmits data from dir (0 = client) in MSS-sized segments, each
// acknowledged by the peer.
func (c *TCPConv) Send(dir int, data []byte) {
	for len(data) > 0 {
		n := min(len(data), c.MSS)
		c.add(dir, PSH|ACK, data[:n])
		c.seq[dir] += uint32(n)
		data = data[n:]
		c.add(1-dir, ACK, nil)
	}
}

// Close sends FIN from both sides.
func (c *TCPConv) Close() {
	c.add(0, FIN|ACK, nil)
	c.seq[0]++
	c.add(1, FIN|ACK, nil)
	c.seq[1]++
	c.add(0, ACK, nil)
}
