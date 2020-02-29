package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Ullaakut/nmap"
)

var wg sync.WaitGroup

func main() {
	var port string
	flag.StringVar(&port, "port", "80,443", "Target ports")

	flag.Parse()

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		domain := strings.ToLower(sc.Text())
		wg.Add(1)
		go portScan(domain, port)
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
		if len(host.Hostnames) == 0 {
			fmt.Printf("Host %q:\n", host.Addresses[0])
		} else {
			fmt.Printf("Host %s %q:\n", host.Hostnames[0], host.Addresses[0])
		}
		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name, port.Service.ExtraInfo)
		}
	}
}
