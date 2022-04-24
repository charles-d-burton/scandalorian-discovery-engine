package main

import (
	"os"
	"strings"

	// Using out of tree due to: https://github.com/google/gopacket/issues/698

	scandaloriantypes "github.com/charles-d-burton/scandalorian-types"
	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
)

/*
 * TODO List:
 * Need to verify that sending interface is IPV4 until I have time to figure out IPV6
 */

type Scan struct {
	scandaloriantypes.PortScan
}

type ConfigSpec struct {
	LogLevel string
	BusHost  string `required:"true"`
	BusPort  string `required:"true"`
}

const (
	streamName   = "discovery"
	durableName  = "discovery"
	subscription = "discovery.requests"
	publish      = "scan-engine.scans"
)

func main() {
	errChan := make(chan error, 10)
	// var json = jsoniter.ConfigCompatibleWithStandardLibrary
	log.SetFormatter(&log.JSONFormatter{})
	var cs ConfigSpec

	err := envconfig.Process("discovery", &cs)
	if err != nil {
		log.Fatal(err)
	}

	switch cs.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	host := cs.BusHost
	var bus MessageBus
	if strings.Contains(host, "nats") {
		var nats NatsConn
		bus = &nats
	} else {
		log.Error("Unknown protocol for message bus host")
	}

	bus.Connect(host, cs.BusPort, errChan)

	go func() {
		laddr, err := getLocalAddress()
		if err != nil {
			log.Fatal(err)
		}

		messageChan := bus.Subscribe(errChan)

		for message := range messageChan {
			log.Info("processing scan")
			var scan *Scan
			err := json.Unmarshal(message.Data, &scan)
			if err != nil {
				errChan <- err
				message.Nak()
				continue
			}
			err = scan.ProcessRequest(laddr)
			if err != nil {
				errChan <- err
				message.Nak()
				continue
			}
			err = bus.Publish(scan)
			if err != nil {
				errChan <- err
				message.Nak()
				continue
			}
			message.Ack()
		}
	}()

	// This should be rethought for liveness/readiness probes instead
	for err := range errChan {
		bus.Close()
		if err != nil {
			log.Fatal(err)
		}
		log.Error("unkonown error")
		os.Exit(1)
	}
}

func (scan *Scan) ProcessRequest(laddr string) error {
	log.Info("start proccessing scan request")
	scanPorts := make([]uint16, 0)
	if len(scan.Ports) == 0 {
		log.Info("no ports defined, scanning everything")
		for i := 0; i <= 65535; i++ {
			scanPorts = append(scanPorts, uint16(i))
		}
	} else {
		log.Info("ports defined, converting to uint16 array")
		for _, port := range scan.Ports {
			scanPorts = append(scanPorts, uint16(port))
		}
	}

	log.Info("scanning ports")
	options := NewScanOptions()
	if scan.PPS != 0 {
		options.PPS = scan.PPS
	}
	if scan.HostScanTimeoutSeconds != 0 {
		options.TimeoutSeconds = scan.HostScanTimeoutSeconds
	}
	foundPorts, err := scanSyn(scanPorts, scan.IP, laddr, options)
	if err != nil {
		return err
	}

	scan.Ports = foundPorts
	return nil
}
