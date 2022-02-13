package main

import (
	"fmt"
	"net"
)

//Ensure that we can listen on the local address
func checkBindPermission(laddr string, proto NetProto) error {
	lnet, err := net.ResolveIPAddr(proto.String(), laddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenIP(proto.String()+":tcp", lnet)
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}

//Get the local non-loopback ip address
func getLocalAddress() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), err
			}
			if ipnet.IP.To16() != nil {
				return ipnet.IP.String(), err
			}
		}
	}
	return "", fmt.Errorf("unable to find local ip address")
}
