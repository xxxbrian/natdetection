package main

import (
	"context"
	"fmt"

	"net"

	"github.com/xxxbrian/natdetection"
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// Greet returns a greeting for the given name
func (a *App) Greet(name string) string {
	natdetection.GetIPInfo("", 0, "", 0)
	return fmt.Sprintf("Hello %s, It's show time!", name)
}

func (a *App) GetDefaulOutboundIP() string {
	// Get Default Outbound IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		fmt.Println(err)
		return "0.0.0.0"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func (a *App) GetIPInfo(sourceIP string) string {
	sourcePort := natdetection.Defaults["source_port"].(int)
	stunPort := natdetection.Defaults["stun_port"].(int)
	stunHost := ""
	natType, externalIP, externalPort, err := natdetection.GetIPInfo(sourceIP, sourcePort, stunHost, stunPort)
	if err != nil {
		return fmt.Sprintf("Error discovering NAT type: %s", err)
	}
	natTypeStr := fmt.Sprintf("%s", natType)
	fmt.Println("NAT Type:", natTypeStr)
	return fmt.Sprintf("%s|%s|%d", natTypeStr, externalIP, externalPort)
}

// return list of all interfaces
func (a *App) GetAllIPv4Interfaces() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var ipv4Addrs []string
	for _, i := range interfaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip.To4() != nil && ip.String() != "127.0.0.1" {
				ipv4Addrs = append(ipv4Addrs, ip.String())
			}
		}
	}
	return ipv4Addrs
}
