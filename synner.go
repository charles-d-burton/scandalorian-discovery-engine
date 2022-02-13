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

func scanSyn(ports []uint16, raddr, laddr string, options *ScanOptions) ([]int, error) {
	var scanOptions *ScanOptions
	if options == nil {
		scanOptions = NewScanOptions()
	}
	scanOptions = options

	dportChan := make(chan uint16, 100)
	defer close(dportChan)

	results := make(chan int, 100)

	ctx, cancel := context.WithCancel(context.Background())
	err := recvSynAck(ctx, results, laddr, raddr, ports, scanOptions.Proto)
	if err != nil {
		cancel()
		log.Debugf("error setting up listener %v", err)
		return nil, err
	}

	err = sendSyn(laddr, raddr, uint16(random(10000, 65535)), dportChan, scanOptions.Proto)
	if err != nil {
		cancel()
		log.Debugf("error sending syn %v", err)
		return nil, err
	}

	var rl ratelimit.Limiter
	rl = ratelimit.New(scanOptions.PPS) //Scan up to 10000 ports per second
	for _, port := range ports {
		rl.Take()
		dportChan <- port
	}

	foundPorts := make([]int, 0)
	to := time.NewTimer(time.Duration(scanOptions.TimeoutSeconds) * time.Second)
	for {
		select {
		case found := <-results:
			foundPorts = append(foundPorts, found)
			to.Reset(time.Duration(scanOptions.TimeoutSeconds) * time.Second)
		case <-to.C:
			cancel()
		}
	}
	return foundPorts, nil
}

//Adapted from https://github.com/JustinTimperio/gomap

func sendSyn(laddr string, raddr string, sport uint16, dportChan <-chan uint16, proto NetProto) error {
	// Create TCP packet struct and header
	// Connect to network interface to send packet
	conn, err := net.Dial(proto.String()+":tcp", raddr)
	if err != nil {
		log.Debug(err)
		return err
	}

	go func(conn net.Conn, dportChan <-chan uint16) {
		defer conn.Close()
		for dport := range dportChan {
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
				Flags:    0x8002, //the SYN flag
				Window:   8192,
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
			buff = new(bytes.Buffer)
			binary.Write(buff, binary.BigEndian, tcpH)

			for i := range op {
				binary.Write(buff, binary.BigEndian, op[i].Kind)
				binary.Write(buff, binary.BigEndian, op[i].Length)
				binary.Write(buff, binary.BigEndian, op[i].Data)
			}
			binary.Write(buff, binary.BigEndian, [6]byte{})

			// Send Packet
			_, err := conn.Write(buff.Bytes())
			if err != nil {
				log.Debugf("unable to write packet to connection %v", err)
			}
		}
	}(conn, dportChan)

	return nil
}

//Listens for packets received that matches both the sender, receivver, and the port defined
//https://blog.des.no/tcpdump-cheat-sheet/
func recvSynAck(ctx context.Context, results chan<- int, laddr string, raddr string, ports []uint16, proto NetProto) error {

	//Generate searchable list of ints
	pints := make([]int, len(ports))
	for i, p := range ports {
		pints[i] = int(p)
	}
	// Checks if the IP address is resolveable
	listenAddr, err := net.ResolveIPAddr(proto.String(), laddr)
	if err != nil {
		return err
	}

	// Connect to network interface to listen for packets
	conn, err := net.ListenIP(proto.String()+":tcp", listenAddr)
	if err != nil {
		return err
	}
	//Wait for packets in a background thread
	go func(ctx context.Context, conn *net.IPConn, raddr string, results chan<- int, pints []int) {
		//This is the only writer for results so it's safe to close here
		defer close(results)

		defer conn.Close()
		// Read each packet looking for ack from raddr on packetport
		for {
			select {
			case <-ctx.Done():
				return
			default:
				buff := make([]byte, 1024)
				_, addr, err := conn.ReadFrom(buff)
				if err != nil {
					log.Debugf("error reading from connection %v", err)
					continue
				}

				//Position 13 is the location of the tcp flags.  0x12 indicates successful handshake
				if addr.String() != raddr || buff[13] != 0x12 {
					continue
				}

				var packetport uint16
				binary.Read(bytes.NewReader(buff), binary.BigEndian, &packetport)

				sorted := sort.SearchInts(pints, int(packetport))
				if sorted < len(pints) {
					log.Debugf("%d ACK", packetport)
					results <- int(packetport)
				}
			}
		}
	}(ctx, conn, raddr, results, pints)
	return nil
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

	//XOR the result
	return ^uint16(sum)
}

//Convert an IPv4 address into a byte array
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
