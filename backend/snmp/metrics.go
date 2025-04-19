package snmp

import (
	"fmt"
	"strings"

	"github.com/gosnmp/gosnmp"
)

type DeviceMetrics struct {
	CPUUsage    string
	CPUIdle     string
	MemTotalKB  string
	MemFreeKB   string
	Processes   string
	Description string
}

func GetDeviceMetrics(params *gosnmp.GoSNMP, sysDescr string) (*DeviceMetrics, error) {
	if strings.Contains(strings.ToLower(sysDescr), "windows") {
		return getWindowsMetrics(params)
	}
	return getLinuxMetrics(params)
}

func getWindowsMetrics(params *gosnmp.GoSNMP) (*DeviceMetrics, error) {
	oids := []string{
		".1.3.6.1.2.1.25.3.3.1.2.1", //Cpu Usage (1 core)
		".1.3.6.1.2.1.25.2.2.0",     // Total Ram
		".1.3.6.1.2.1.25.1.6.0",     // Running processes
	}

	res, err := params.Get(oids)
	if err != nil {
		return nil, fmt.Errorf("SNMP get (Windows metrics) failed: %v", err)
	}

	fmt.Println("Scanning window device ...")

	metrics := &DeviceMetrics{}
	for _, v := range res.Variables {
		switch v.Name {
		case ".1.3.6.1.2.1.25.3.3.1.2.1":
			metrics.CPUUsage = fmt.Sprint(v.Value)
		case ".1.3.6.1.2.1.25.2.2.0":
			metrics.MemTotalKB = fmt.Sprint(v.Value)
		case ".1.3.6.1.2.1.25.1.6.0":
			metrics.MemFreeKB = fmt.Sprint(v.Value)
		}
	}
	return metrics, nil
}

func getLinuxMetrics(params *gosnmp.GoSNMP) (*DeviceMetrics, error) {
	oids := []string{
		".1.3.6.1.4.1.2021.11.9.0",  //Cpu user (%)
		".1.3.6.1.4.1.2021.11.11.0", //CPU Idle (%)
		".1.3.6.1.4.1.2021.4.5.0",   // Total Ram
		".1.3.6.1.4.1.2021.4.6.0",   // Running processes
	}

	res, err := params.Get(oids)
	if err != nil {
		return nil, fmt.Errorf("SNMP get (Linux metrics) failed: %v", err)
	}

	fmt.Println("Scanning linux device ...")

	metrics := &DeviceMetrics{}
	for _, v := range res.Variables {
		switch v.Name {
		case ".1.3.6.1.4.1.2021.11.9.0":
			metrics.CPUUsage = fmt.Sprint(v.Value)
		case ".1.3.6.1.4.1.2021.11.11.0":
			metrics.CPUIdle = fmt.Sprint(v.Value)
		case ".1.3.6.1.4.1.2021.4.5.0":
			metrics.MemTotalKB = fmt.Sprint(v.Value)
		case ".1.3.6.1.4.1.2021.4.6.0":
			metrics.MemFreeKB = fmt.Sprint(v.Value)
		}
	}
	return metrics, nil
}
