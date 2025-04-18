package main

import (
	"fmt"

	"github.com/abhishek-sengar/RTNTV/snmp"
)

func main() {
	fmt.Println("Hello go")

	subnet, err := snmp.GetLocalSubnet()
	if err != nil {
		fmt.Printf("Error in finding subnet %v\n", err)
	}

	fmt.Printf("Sunbet: %v\n", subnet)

	devices := snmp.ScanSubnet(subnet)

	fmt.Printf("Devices %v", devices)
}
