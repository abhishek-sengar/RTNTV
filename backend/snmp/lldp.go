package snmp

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

func formatMAC(b []byte) string {
	parts := make([]string, len(b))

	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":")
}

func getArpMap(targetIP string) (map[string]string, error) {
	params := &gosnmp.GoSNMP{
		Target:    targetIP,
		Port:      161,
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   2 * time.Second,
	}
	if err := params.Connect(); err != nil {
		return nil, fmt.Errorf("SNMP connect failed: %v", err)
	}

	defer params.Conn.Close()

	arpOID := "1.3.6.1.2.1.4.22.1.2"
	arpMap := make(map[string]string)

	err := params.Walk(arpOID, func(pdu gosnmp.SnmpPDU) error {
		macBytes, ok := pdu.Value.([]byte)
		if !ok {
			return nil
		}

		mac := formatMAC(macBytes)

		suffix := strings.TrimPrefix(pdu.Name, arpOID+".")

		parts := strings.Split(suffix, ".")

		ip := strings.Join(parts[len(parts)-4:], ":")
		if net.ParseIP(ip) != nil {
			arpMap[mac] = ip
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("ARP Walk failed: %v", err)
	}
	return arpMap, nil

}

func ScanLLDPNeighbours(targetIP string) ([]string, error) {
	params := &gosnmp.GoSNMP{
		Target:    targetIP,
		Port:      161,
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   2 * time.Second,
	}

	if err := params.Connect(); err != nil {
		return nil, fmt.Errorf("SNMP connect failed: %v", err)
	}
	defer params.Conn.Close()

	arpMap, err := getArpMap(targetIP)

	if err != nil {
		return nil, err
	}

	chassisOID := "1.0.8802.1.1.2.1.4.1.1.5"

	neighbourIPs := []string{}

	err = params.Walk(chassisOID, func(pdu gosnmp.SnmpPDU) error {
		macBytes, ok := pdu.Value.([]byte)

		if !ok {
			return nil
		}

		mac := formatMAC(macBytes)
		if ip, found := arpMap[mac]; found {
			neighbourIPs = append(neighbourIPs, ip)
		}
		return nil

	})

	if err != nil {
		return nil, fmt.Errorf("LLDP walk failed: %v", err)
	}

	uniq := make(map[string]struct{}, len(neighbourIPs))

	result := []string{}

	for _, ip := range neighbourIPs {
		if _, seen := uniq[ip]; !seen {
			uniq[ip] = struct{}{}
			result = append(result, ip)
		}
	}
	return result, nil

}
