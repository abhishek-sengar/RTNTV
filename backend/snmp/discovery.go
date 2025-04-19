package snmp

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

func GetDefaultGateway() (string, error) {
	out, err := exec.Command("powershell",
		"-command",
		"Get-NetRoute -DestinationPrefix 0.0.0.0/0 | "+
			"Sort-Object RouteMetric | "+
			"Select-Object -First 1 -ExpandProperty NextHop").Output()

	if err != nil {
		return "", err
	}
	gw := strings.TrimSpace(string(out))

	if net.ParseIP(gw) == nil {
		return "", fmt.Errorf("Invalid gateway IP: %v", gw)
	}
	return gw, nil

}

func getConnectedDevices(ip string) ([]string, error) {
	params := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   2 * time.Second,
		Retries:   1,
	}

	if err := params.Connect(); err != nil {
		return nil, fmt.Errorf("Snmp connect failed: %v", err)
	}
	defer params.Conn.Close()

	oid := "1.3.6.1.2.1.4.22.1.1"

	var ips []string
	err := params.Walk(oid, func(pdu gosnmp.SnmpPDU) error {
		parts := strings.Split(pdu.Name, ".")

		if (len(parts)) >= 4 {
			ip := fmt.Sprintf("%s.%s.%s.%s", parts[len(parts)-4], parts[len(parts)-3], parts[len(parts)-2], parts[len(parts)-1])
			if net.ParseIP(ip) != nil {
				ips = append(ips, ip)
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("SNMP Walk failed: %v", err)
	}

	return ips, nil
}

func isRouterOrSwitch(ip string) bool {
	params := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   2 * time.Second,
		Retries:   1,
	}

	if err := params.Connect(); err != nil {
		return false
	}

	defer params.Conn.Close()

	routeOID := "1.3.6.1.2.1.4.21.1.1"
	switchOID := "1.3.6.1.2.1.17.1.1.0"

	for _, oid := range []string{routeOID, switchOID} {
		result, err := params.Get([]string{oid})
		if err == nil && len(result.Variables) > 0 {
			return true
		}
	}
	return false

}

func BFSDiscovery(startIP string) ([]*DiscoveredDevice, error) {
	visited := make(map[string]bool)

	var mu sync.Mutex
	queue := []string{startIP}

	var devices []*DiscoveredDevice
	var wg sync.WaitGroup

	for len(queue) > 0 {
		ip := queue[0]
		queue = queue[1:]

		mu.Lock()
		if visited[ip] {
			mu.Unlock()
			continue
		}
		visited[ip] = true
		mu.Unlock()

		wg.Add(1)

		go func(ip string) {
			defer wg.Done()
			device, err := scanHost(ip)
			if err != nil {
				fmt.Printf("ScanHost (%s): %v\n", ip, err)
				return
			}
			mu.Lock()

			devices = append(devices, device)
			mu.Unlock()

			fmt.Printf("Discovered %s %s\n", device.Name, ip)

			if isRouterOrSwitch(ip) {
				fmt.Printf("%s is not a router/switch", ip)
				return
			}

			neighbours, err := ScanLLDPNeighbours(ip)
			if err != nil || len(neighbours) == 0 {
				neighbours, err = getConnectedDevices(ip)
				if err != nil {
					fmt.Printf("GetConnectedDevices(%s): %v\n", ip, err)
					return
				}
			}

			for _, nei := range neighbours {
				mu.Lock()
				if !visited[nei] {
					queue = append(queue, nei)
				}
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	return devices, nil

}

func StartDiscovery() {
	startIP, err := GetLocalRouterIP()
	if err != nil {
		fmt.Println("Failed to get local router  IP:", err)
		return
	}

	fmt.Println("Starting discovery from router: ", startIP)

	topology, err := BFSDiscovery(startIP)
	if err != nil {
		fmt.Println("Discovery Failed.", err)
	}

	fmt.Println("Discovery Complete.")

	for _, d := range topology {
		fmt.Printf("IP: %s | Name: %s ", d.IPAddress, d.Name)
	}

}
