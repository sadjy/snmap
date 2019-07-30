package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Ullaakut/nmap"
)

var wg sync.WaitGroup

func main() {
	var target string
	flag.StringVar(&target, "target", "N/A", "Target ip address")

	var port string
	flag.StringVar(&port, "port", "80,443", "Target ports")

	flag.Parse()

	for _, t := range strings.Split(target, ",") {
		wg.Add(1)
		go portScan(t, port)
	}
	wg.Wait()
}

func portScan(target string, ports string) {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithPorts(ports),
		nmap.WithServiceInfo(),
		nmap.WithContext(ctx),
		nmap.WithOpenOnly(),
	)
	if err != nil {
		log.Fatalf("Unable to create nmap scanner: %v", err)
	}

	result, err := scanner.Run()
	if err != nil {
		log.Fatalf("Unable to run nmap scan: %v", err)
	}

	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		fmt.Printf("Host %q %s:\n", host.Addresses[0], host.Hostnames[0])
		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name, port.Service.ExtraInfo)
		}
	}
}
