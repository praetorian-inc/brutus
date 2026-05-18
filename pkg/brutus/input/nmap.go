// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package input

import (
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// nmapRun is the root element of nmap XML output (-oX).
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Hostnames nmapHostnames `xml:"hostnames"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostnames struct {
	Hostnames []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	Tunnel  string `xml:"tunnel,attr"`
}

// LoadNmapFile parses an nmap XML file (-oX output) and returns a slice of
// NervaResult for each open port. Hosts that are not "up" and ports that are
// not "open" are skipped. The nmap service name is normalized and mapped
// through MapServiceToProtocol; unknown services have Protocol set to "" so
// callers can skip or fingerprint them.
func LoadNmapFile(filePath string) ([]NervaResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening nmap file: %w", err)
	}

	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parsing nmap XML: %w", err)
	}

	var results []NervaResult
	for _, host := range run.Hosts {
		if host.Status.State != "up" {
			continue
		}

		ip := extractNmapIP(host.Addresses)
		hostname := extractNmapHostname(host.Hostnames)

		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}

			portNum, err := strconv.Atoi(port.PortID)
			if err != nil {
				continue
			}

			tls := strings.EqualFold(port.Service.Tunnel, "ssl")
			version := buildNmapVersion(port.Service.Product, port.Service.Version)

			serviceName := normalizeNmapService(port.Service.Name)
			protocol := MapServiceToProtocol(serviceName)

			// Upgrade http to https when TLS tunnel is detected.
			if tls && protocol == "http" {
				protocol = "https"
			}

			results = append(results, NervaResult{
				Host:      hostname,
				IP:        ip,
				Port:      portNum,
				Protocol:  protocol,
				TLS:       tls,
				Transport: port.Protocol,
				Version:   version,
			})
		}
	}

	return results, nil
}

// extractNmapIP returns the first IPv4 or IPv6 address from the address list.
func extractNmapIP(addrs []nmapAddress) string {
	for _, a := range addrs {
		if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
			return a.Addr
		}
	}
	return ""
}

// extractNmapHostname returns the first hostname entry.
func extractNmapHostname(hostnames nmapHostnames) string {
	for _, h := range hostnames.Hostnames {
		if h.Name != "" {
			return h.Name
		}
	}
	return ""
}

// buildNmapVersion concatenates product and version strings.
func buildNmapVersion(product, version string) string {
	var parts []string
	if product != "" {
		parts = append(parts, product)
	}
	if version != "" {
		parts = append(parts, version)
	}
	return strings.Join(parts, " ")
}

// normalizeNmapService handles nmap-specific service name variations that
// differ from the names in MapServiceToProtocol.
func normalizeNmapService(name string) string {
	name = strings.ToLower(name)
	switch name {
	case "ms-sql-s", "ms-sql":
		return "mssql"
	case "microsoft-ds", "netbios-ssn":
		return "smb"
	case "http-proxy", "http-alt":
		return "http"
	case "ssl/http", "https-alt":
		return "https"
	case "ms-wbt-server":
		return "rdp"
	}
	return name
}
