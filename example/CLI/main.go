package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"natdetection"
)

func main() {
	// Set CLI flags
	jsonOutput := flag.Bool("json", false, "JSON output")
	stunHost := flag.String("stun-host", "", "STUN host to use")
	stunPort := flag.Int("stun-port", natdetection.Defaults["stun_port"].(int), "STUN host port to use")
	sourceIP := flag.String("source-ip", natdetection.Defaults["source_ip"].(string), "network interface for client")
	sourcePort := flag.Int("source-port", natdetection.Defaults["source_port"].(int), "port to listen on for client")
	version := flag.Bool("version", false, "show version")

	flag.Parse()

	// Show version
	if *version {
		fmt.Println("Version:", natdetection.Version)
		return
	}

	fmt.Println("- Discovering NAT type (it may take 5 to 60 seconds) ...")

	// Get NAT type
	natType, externalIP, externalPort, err := natdetection.GetIPInfo(*sourceIP, *sourcePort, *stunHost, *stunPort)
	if err != nil {
		fmt.Println("Error discovering NAT type: ", err)
	}

	if *jsonOutput {
		jsonData, _ := json.MarshalIndent(map[string]interface{}{
			"type":          natType,
			"external_ip":   externalIP,
			"external_port": externalPort,
		}, "", "  ")
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("\tNAT Type: %s\n", natType)
		fmt.Printf("\tExternal IP: %s\n", externalIP)
		fmt.Printf("\tExternal Port: %d\n", externalPort)
	}
}
