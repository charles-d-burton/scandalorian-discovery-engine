package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"go.uber.org/ratelimit"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	level := os.Getenv("LOG_LEVEL")
	if level == "DEBUG" {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}
}

// scanSyn take a list of ports and scan all of them
func scanSyn(ports []uint16, raddr, laddr string, options *ScanOptions) ([]int, error) {
	var scanOptions *ScanOptions
	if options == nil {
		scanOptions = NewScanOptions()
	}
	scanOptions = options
	dportChan := make(chan uint16, 100) // Want to keep writer busy but not finish so fast that the reciver doesn't get anything back
	results := make(chan int, 100)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		err := recvSynAck(ctx, results, laddr, raddr, ports, scanOptions.Proto)
		if err != nil {
			cancel()
			log.Fatalf("error setting up listener %v", err) // Fatal because it should be able to listen
		}
	}()

	go func() {
		err := sendSyn(laddr, raddr, dportChan, scanOptions.Proto)
		if err != nil {
			cancel()                                // Stop receiver
			log.Fatalf("error sending syn %v", err) // Fatal, can't open connection
		}
	}()

    rl := ratelimit.New(scanOptions.PPS) // Scan up to 10000 ports per second
	for _, port := range ports {
		rl.Take()
		dportChan <- port
	}
	close(dportChan) // Explicit close so senSyn stops

	foundPorts := make([]int, 0)

	ticker := time.NewTicker(time.Duration(scanOptions.TimeoutSeconds) * time.Second)
	for {
		select {
		case found := <-results:
			foundPorts = append(foundPorts, found)
			ticker.Stop()
			ticker.Reset(time.Duration(scanOptions.TimeoutSeconds) * time.Second)
		case <-ticker.C:
			cancel()
			return foundPorts, nil
		}
	}
}

// Adapted from https://github.com/JustinTimperio/gomap
func sendSyn(laddr string, raddr string, dportChan <-chan uint16, proto NetProto) error {
	// Create TCP packet struct and header
	// Connect to network interface to send packet
	for dport := range dportChan {
		conn, err := net.Dial(proto.String()+":tcp", raddr)
		if err != nil {
			log.Debug(err)
			return err
		}

		sport := uint16(random(10000, 65535))
		// log.Debugf("sending scan for port %d", dport)
		op := []tcpOption{
			{
				Kind:   2,
				Length: 4,
				Data:   []byte{0x05, 0xb4},
			},
			{
				Kind: 0,
			},
		}

		tcpH := tcpHeader{
			Src:      sport,
			Dst:      dport,
			Seq:      rand.Uint32(),
			Ack:      0,
			Flags:    0x8002, // the SYN flag
			Window:   1024,
			ChkSum:   0,
			UPointer: 0,
		}

		// Build dummy packet for checksum
		buff := new(bytes.Buffer)
		binary.Write(buff, binary.BigEndian, tcpH)

		for i := range op {
			binary.Write(buff, binary.BigEndian, op[i].Kind)
			binary.Write(buff, binary.BigEndian, op[i].Length)
			binary.Write(buff, binary.BigEndian, op[i].Data)
		}

		binary.Write(buff, binary.BigEndian, [6]byte{})
		data := buff.Bytes()
		checkSum := checkSum(data, ipstr2Bytes(laddr), ipstr2Bytes(raddr))
		tcpH.ChkSum = checkSum

		// Build final packet
		binary.Write(buff, binary.BigEndian, tcpH)

		for i := range op {
			binary.Write(buff, binary.BigEndian, op[i].Kind)
			binary.Write(buff, binary.BigEndian, op[i].Length)
			binary.Write(buff, binary.BigEndian, op[i].Data)
		}
		binary.Write(buff, binary.BigEndian, [6]byte{})

		// Send Packet
		_, err = conn.Write(buff.Bytes())
		if err != nil {
			log.Debugf("unable to write packet to connection %v", err)
		}
        conn.Close()
	}
	log.Debug("finished sending packets")

	return nil
}

// Listens for packets received that matches both the sender, receivver, and the port defined
// https://blog.des.no/tcpdump-cheat-sheet/
func recvSynAck(ctx context.Context, results chan<- int, laddr string, raddr string, ports []uint16, proto NetProto) error {
	pints := make([]int, len(ports))
	for i, p := range ports {
		pints[i] = int(p)
	}
	sort.Ints(pints)

	listenAddr, err := net.ResolveIPAddr(proto.String(), laddr)
	if err != nil {
		return err
	}

	// Connect to network interface to listen for packets
	conn, err := net.ListenIP(proto.String()+":tcp", listenAddr)
	if err != nil {
		return err
	}
	defer close(results)
	defer conn.Close()

	for {
		select {
		case <-ctx.Done():
			log.Debug("shutting down receiver")
			return nil
		default:
			buff := make([]byte, 1024)
			pcount, addr, err := conn.ReadFrom(buff)
			log.Debugf("read %d packets from socket", pcount)
			if err != nil {
				log.Debugf("error reading from connection %v", err)
				continue
			}

            log.Debugf("raddr: %s", raddr)
            log.Debugf("addrstring: %s", addr.String())
			// Position 13 is the location of the tcp flags.  0x12 indicates successful handshake
			if addr.String() != raddr || buff[13] != 0x12 {
                log.Debug("packet does not match")
				continue
			}

			var packetport uint16
			binary.Read(bytes.NewReader(buff), binary.BigEndian, &packetport)

			sorted := sort.SearchInts(pints, int(packetport))
			if sorted < len(pints) {
				log.Debugf("%d ACK", packetport)
				results <- int(packetport)
                continue
			} 
            log.Debug("no match")
		}
	}
}

/* Generate a pseudoheader
 * This is added during the checksum calculation.  This is not sent as part of the TCP segment,
 * rather is assures the receiver that a routing or fragmentation process did no modify the
 * important fields of the IP header
 * https://www.oreilly.com/library/view/windows-server-2008/9780735624474/ch10s06.html#:~:text=The%20TCP%20pseudo%20header%20is%20added%20to%20the%20beginning%20of,fields%20in%20the%20IP%20header.
 */

func checkSum(data []byte, src, dst [4]byte) uint16 {
	// 4 bytes from srce
	// 4 bytes from dst
	// unused
	// 6 (static)
	// unused
	// length of data
	pseudoHeader := []byte{
		src[0], src[1], src[2], src[3],
		dst[0], dst[1], dst[2], dst[3],
		0,
		6,
		0,
		byte(len(data)),
	}

	totalLength := len(pseudoHeader) + len(data)
	if totalLength%2 != 0 {
		totalLength++
	}

	d := make([]byte, 0, totalLength)
	d = append(d, pseudoHeader...)
	d = append(d, data...)

	var sum uint32
	for i := 0; i < len(d)-1; i += 2 {
		sum += uint32(uint16(d[i])<<8 | uint16(d[i+1]))
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	// XOR the result
	return ^uint16(sum)
}

// Convert an IPv4 address into a byte array
func ipstr2Bytes(addr string) [4]byte {
	s := strings.Split(addr, ".")
	b0, _ := strconv.Atoi(s[0])
	b1, _ := strconv.Atoi(s[1])
	b2, _ := strconv.Atoi(s[2])
	b3, _ := strconv.Atoi(s[3])
	return [4]byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}

func random(min, max int) int {
	return rand.Intn(max-min) + min
}
