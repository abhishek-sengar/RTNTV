package snmp

import (
	"bytes"
	"errors"
	"os/exec"
	"runtime"
	"strings"
)

func GetLocalRouterIP() (string, error) {
	switch runtime.GOOS {
	case "windows":
		return getRouterIPWindows()
	case "linux", "darwin":
		return getRouterIPUnix()
	default:
		return "", errors.New("Unsupported os")
	}
}

func getRouterIPWindows() (string, error) {
	cmd := exec.Command("route", "print", "0.0.0.0")

	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return "", err
	}

	lines := strings.Split(out.String(), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "0.0.0.0") {
			fields := strings.Fields(line)
			if len(fields) > 3 {
				return fields[2], nil
			}
		}
	}

	return "", errors.New("Gateway not found")
}

func getRouterIPUnix() (string, error) {
	cmd := exec.Command("sh", "-c", "ip route | grep default")

	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return "", err
	}

	fields := strings.Fields(out.String())

	for i, field := range fields {
		if field == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", errors.New("Gateway not found")
}
