package main

import (
	"os"
	"strings"

	// Using out of tree due to: https://github.com/google/gopacket/issues/698

	scandaloriantypes "github.com/charles-d-burton/scandalorian-types"
	"github.com/kelseyhightower/envconfig"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	errChan := make(chan error, 10)
	// var json = jsoniter.ConfigCompatibleWithStandardLibrary
	var cs ConfigSpec

	err := envconfig.Process("discovery", &cs)
	if err != nil {
        log.Fatal().Err(err).Msg("unable to start due to missing environment variables")
	}

	switch cs.LogLevel {
	case "debug":
        zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
        zerolog.SetGlobalLevel(zerolog.InfoLevel)
	default:
        zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	host := cs.BusHost
	var bus MessageBus
	if strings.Contains(host, "nats") {
		var nats NatsConn
		bus = &nats
	} else {
		log.Error().Msg("Unknown protocol for message bus host")
	}

	bus.Connect(host, cs.BusPort, errChan)

	go func() {
		laddr, err := getLocalAddress()
		if err != nil {
			log.Fatal().Err(err)
		}

		messageChan := bus.Subscribe(errChan)

		for message := range messageChan {
			log.Info().Msg("processing scan")
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
			log.Fatal().Err(err)
		}
		log.Error().Msg("unkonown error")
		os.Exit(1)
	}
}

func (scan *Scan) ProcessRequest(laddr string) error {
	log.Info().Msg("start proccessing scan request")
	scanPorts := make([]uint16, 0)
	if len(scan.Ports) == 0 {
		log.Info().Msg("no ports defined, scanning everything")
		for i := 0; i <= 65535; i++ {
			scanPorts = append(scanPorts, uint16(i))
		}
	} else {
		log.Info().Msg("ports defined, converting to uint16 array")
		for _, port := range scan.Ports {
			scanPorts = append(scanPorts, uint16(port))
		}
	}

	log.Info().Msg("scanning ports")
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
