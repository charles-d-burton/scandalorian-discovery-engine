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

type Result struct {
	Port  int
	Found bool
}

/*type ScanResult struct {
	Host  string
	IP    []net.IP
	Ports []int
}*/

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
