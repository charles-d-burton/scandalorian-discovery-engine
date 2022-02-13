package main

//Adapted from the excellent worker here:
//https://github.com/JustinTimperio/gomap/blob/master/gomap.go

type NetProto int

//declare the protocol enum type
const (
	IPV4 NetProto = iota
	IPV6
)

func (proto NetProto) String() string {
	switch proto {
	case IPV4:
		return "ip4"
	case IPV6:
		return "ip6"
	}
	return "unkown"
}

type ScanOptions struct {
	Proto          NetProto
	TimeoutSeconds int
	PPS            int
}

//New Set the default options of IPV4, 3 second Timeout, 15000 Packets Per Second
func NewScanOptions() *ScanOptions {
	return &ScanOptions{Proto: IPV4, TimeoutSeconds: 3, PPS: 15000}
}

type tcpHeader struct {
	Src      uint16
	Dst      uint16
	Seq      uint32
	Ack      uint32
	Flags    uint16
	Window   uint16
	ChkSum   uint16
	UPointer uint16
}

type tcpOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}
