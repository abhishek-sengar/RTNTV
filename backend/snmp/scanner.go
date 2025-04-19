package snmp

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

type DiscoveredDevice struct {
	IPAddress string
	Name      string
	UpTime    string
	SysDesc   string
	DevMet    DeviceMetrics
}

func scanHost(ip string) (*DiscoveredDevice, error) {
	params := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   2 * time.Second,
		Retries:   1,
	}

	err := params.Connect()
	if err != nil {
		return nil, fmt.Errorf("SNMP connect failed: %v", err)
	}

	defer params.Conn.Close()

	oids := []string{
		"1.3.6.1.2.1.1.5.0", //sysName
		"1.3.6.1.2.1.1.3.0", //sysName
		"1.3.6.1.2.1.1.1.0", //sysName
	}

	result, err := params.Get(oids)

	if err != nil {
		return nil, fmt.Errorf("SNMP get failed: %v", err)
	}

	//fmt.Printf("Result %v", result)

	device := &DiscoveredDevice{IPAddress: ip}
	for _, variable := range result.Variables {
		switch variable.Name {
		case ".1.3.6.1.2.1.1.5.0":
			device.Name = string(variable.Value.([]byte))
		case ".1.3.6.1.2.1.1.3.0":
			device.UpTime = fmt.Sprint(variable.Value)
		case ".1.3.6.1.2.1.1.1.0":
			device.SysDesc = string(variable.Value.([]byte))
		}

		fmt.Println(device.IPAddress)
		fmt.Println("Finding Device Metrices ...")

		metrics, err := GetDeviceMetrics(params, device.SysDesc)
		fmt.Println(metrics)
		if err == nil && metrics != nil {
			device.DevMet.CPUUsage = metrics.CPUUsage
			device.DevMet.CPUIdle = metrics.CPUIdle
			device.DevMet.MemTotalKB = metrics.MemTotalKB
			device.DevMet.MemFreeKB = metrics.MemFreeKB
			device.DevMet.Processes = metrics.Processes
		}
	}

	return device, nil
}

func ScanSubnet(subnet string) []*DiscoveredDevice {
	ip, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		fmt.Println("Invalid subnet:", err)
		return nil
	}

	var (
		discovered  []*DiscoveredDevice
		mutex       sync.Mutex
		wg          sync.WaitGroup
		concurrency = 250
		semaphore   = make(chan struct{}, concurrency)
	)

	fmt.Println("Scanning subnetworks ....... ..... ......")

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		currentIP := ip.String()
		if strings.HasSuffix(currentIP, ".0") || strings.HasSuffix(currentIP, ".255") {
			continue
		}

		semaphore <- struct{}{}
		wg.Add(1)

		go func(ip string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			device, err := scanHost(ip)
			if err == nil && device != nil {
				mutex.Lock()
				discovered = append(discovered, device)
				mutex.Unlock()
				fmt.Printf("\nFound Device: \n\tName: %s\n\tIP: %s\n\tDesc: %s\n\tUptime:  %s\n", device.Name, currentIP, device.SysDesc, device.UpTime)
			} else {
				//fmt.Printf("Not Found: %s \n", currentIP)
			}
		}(currentIP)
	}

	wg.Wait()
	return discovered
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func GetLocalSubnet() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "Error: ", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			var ipnet *net.IPNet

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				ipnet = v
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			fmt.Println(ip)

			return ipnet.String(), nil
		}

	}

	return "", fmt.Errorf("no valid network interface founnd")

}
