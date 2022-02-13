package main

import (
	"os"
	"strings"

	//Using out of tree due to: https://github.com/google/gopacket/issues/698

	scandaloriantypes "github.com/charles-d-burton/scandalorian-types"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

/*
 * TODO List:
 * Need to verify that sending interface is IPV4 until I have time to figure out IPV6
 */

type Scan struct {
	scandaloriantypes.PortScan
}

const (
	streamName   = "discovery"
	durableName  = "discovery"
	subscription = "discovery.requests"
	publish      = "scan-engine.scans"
	//rateLimit    = 1000 //Upper boundary for how fast to scan a host TODO: convert to tunable
	maxSamples  = 50
	maxDuration = 2 //Average number of seconds a scan is taking,  TODO: should convert to tunable
)

func main() {
	errChan := make(chan error, 10)
	//var json = jsoniter.ConfigCompatibleWithStandardLibrary
	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.DebugLevel) //TODO: Remember to reset
	v := viper.New()
	v.SetEnvPrefix("engine")
	v.AutomaticEnv()
	if !v.IsSet("port") || !v.IsSet("host") {
		log.Fatal("Must set host and port for message bus")
	}

	if !v.IsSet("log_level") {
		log.SetLevel(log.InfoLevel)
	} else {
		level, err := log.ParseLevel(v.GetString("log_level"))
		if err != nil {
			log.SetLevel(log.InfoLevel)
			log.Warn(err)
		} else {
			log.Info("setting log level to %v", level)
			log.SetLevel(level)
		}
	}
	host := v.GetString("host")
	var bus MessageBus
	if strings.Contains(host, "nats") {
		var nats NatsConn
		bus = &nats
	} else {
		log.Error("Unknown protocol for message bus host")
	}

	bus.Connect(host, v.GetString("port"), errChan)

	laddr, err := getLocalAddress()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		messageChan := bus.Subscribe(errChan)
		for message := range messageChan {
			log.Debug("processing scan")
			var scan *Scan
			err := json.Unmarshal(message.Data, &scan)
			if err != nil {
				errChan <- err
				break
			}
			err = scan.ProcessRequest(bus, laddr)
			if err != nil {
				errChan <- err
				message.Nak()
				break
			}
			message.Ack()
		}
	}()

	//This should be rethought for liveness/readiness probes instead
	for err := range errChan {
		bus.Close()
		if err != nil {
			log.Fatal(err)
		}
		log.Error("unkonown error")
		os.Exit(1)
	}
}

func (scan *Scan) ProcessRequest(bus MessageBus, laddr string) error {
	log.Debug("start proccessing scan request")
	scanPorts := make([]uint16, 0)
	if len(scan.Ports) == 0 {
		log.Debug("no ports defined, scanning everything")
		for i := 0; i <= 65535; i++ {
			scanPorts = append(scanPorts, uint16(i))
		}
	} else {
		log.Debug("ports defined, converting to uint16 array")
		for _, port := range scan.Ports {
			scanPorts = append(scanPorts, uint16(port))
		}
	}

	log.Debug("scanning ports")
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
	return bus.Publish(scan)

}
