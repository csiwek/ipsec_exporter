package ipsec

import (
	"github.com/prometheus/common/log"
	"os/exec"
	"regexp"
	"strconv"
	//	"fmt"
)

type userstatus struct {
	up          bool
	status      connectionStatus
	uname       string
	ubytesIn    int
	ubytesOut   int
	upacketsIn  int
	upacketsOut int
	utsipaddr   string // user tunnel source IP addr
	uipaddr     string // user VPN source IP addr
}

type tunnelstatus struct {
	up         bool
	status     connectionStatus
	bytesIn    int
	bytesOut   int
	packetsIn  int
	packetsOut int
}

type connectionStatus int

const (
	tunnelInstalled       connectionStatus = 0
	connectionEstablished connectionStatus = 1
	down                  connectionStatus = 2
	unknown               connectionStatus = 3
	ignored               connectionStatus = 4
)

type statusProvider interface {
	statusOutput(tunnel connection) (string, error)
}

type cliStatusProvider struct {
}

func (c *cliStatusProvider) statusOutput(tunnel connection) (string, error) {
	cmd := exec.Command("ipsec", "statusall", tunnel.name)
	out, err := cmd.Output()
	//	fmt.Println("Error: ", err,"\nvar output:\n",string(out))
	if err != nil {
		return "", err
	}

	return string(out), nil
}

func queryTunnelStatus(ipSecConfiguration connection, provider statusProvider) map[string]*tunnelstatus {
	statusMap := map[string]*tunnelstatus{}

	if ipSecConfiguration.ignored {
		statusMap[ipSecConfiguration.name] = &tunnelstatus{
			up:     true,
			status: ignored,
		}
		return statusMap
	}

	if out, err := provider.statusOutput(ipSecConfiguration); err != nil {
		log.Warnf("Unable to retrieve the status of tunnel '%s'. Reason: %v", ipSecConfiguration.name, err)
		statusMap[ipSecConfiguration.name] = &tunnelstatus{
			up:     false,
			status: unknown,
		}
	} else {
		statusMap[ipSecConfiguration.name] = &tunnelstatus{
			up:         true,
			status:     extractStatus([]byte(out)),
			bytesIn:    extractIntWithRegex(out, `([[0-9]+) bytes_i`),
			bytesOut:   extractIntWithRegex(out, `([[0-9]+) bytes_o`),
			packetsIn:  extractIntWithRegex(out, `bytes_i \(([[0-9]+) pkts`),
			packetsOut: extractIntWithRegex(out, `bytes_o \(([[0-9]+) pkts`),
		}
	}
	return statusMap
}

func queryUserStatus(ipSecConfiguration connection, provider statusProvider) map[string]map[string]*userstatus {
	statusMap := map[string]map[string]*userstatus{}

	var rout string
	_uname := ""
	_ubytesIn := -1
	_ubytesOut := -1
	_upacketsIn := -1
	_upacketsOut := -1

	if ipSecConfiguration.ignored {
		statusMap[ipSecConfiguration.name] = map[string]*userstatus{}
		statusMap[ipSecConfiguration.name][_uname] = &userstatus{
			up:     true,
			status: ignored,
		}
		return statusMap
	}

	if out, err := provider.statusOutput(ipSecConfiguration); err != nil {
		log.Warnf("Unable to retrieve the status of tunnel '%s'. Reason: %v", ipSecConfiguration.name, err)
		statusMap[ipSecConfiguration.name] = map[string]*userstatus{}
		statusMap[ipSecConfiguration.name][_uname] = &userstatus{
			up:     false,
			status: unknown,
		}
	} else {
		if statusMap[ipSecConfiguration.name] == nil {
			statusMap[ipSecConfiguration.name] = map[string]*userstatus{}
		}
		statusMap[ipSecConfiguration.name][_uname] = &userstatus{
			up:     true,
			status: extractStatus([]byte(out)),
		}
		for _, out2 := range out {

			rout += string(out2)

			if ipSecConfiguration.auth == "eap" {
				// to catch the local ID
				_uname = extractStringWithRegex(rout, `\]\.\.\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\[([0-9a-zA-Z]+)\]`)
				if _uname == "" {
					//if local id is empty, get remote EAP ID
					_uname = extractStringWithRegex(rout, `Remote EAP identity: ([0-9a-zA-Z]+)`)
				}
			} else if ipSecConfiguration.auth == "xauth" {
				_uname = extractStringWithRegex(rout, `Remote XAuth identity: ([0-9a-zA-Z]+)`)
			} else {
				_uname = extractStringWithRegex(rout, `=== ([0-9a-zA-Z\.\/]+)`)
			}

			_ubytesIn = extractIntWithRegex(rout, `([[0-9]+) bytes_i`)
			_ubytesOut = extractIntWithRegex(rout, `([[0-9]+) bytes_o`)
			_upacketsIn = extractIntWithRegex(rout, `bytes_i \(([[0-9]+) pkts`)
			_upacketsOut = extractIntWithRegex(rout, `bytes_o \(([[0-9]+) pkts`)

			// if vars not with default values, update statusmap
			if _uname != "" && _ubytesIn != -1 && _ubytesOut != -1 && _upacketsIn != -1 && _upacketsOut != -1 {
				if statusMap[ipSecConfiguration.name] == nil {
					statusMap[ipSecConfiguration.name] = map[string]*userstatus{}
				}
				statusMap[ipSecConfiguration.name][_uname] = &userstatus{
					up:          true,
					status:      extractStatus([]byte(out)),
					uname:       _uname,
					ubytesIn:    _ubytesIn,
					ubytesOut:   _ubytesOut,
					upacketsIn:  _upacketsIn,
					upacketsOut: _upacketsOut,
				}
				// reset var values
				_uname = ""
				_ubytesIn = -1
				_ubytesOut = -1
				_upacketsIn = -1
				_upacketsOut = -1
				rout = ""
			}
		}
	}
	return statusMap
}

func extractStatus(statusLine []byte) connectionStatus {
	noMatchRegex := regexp.MustCompile(`no match`)
	tunnelEstablishedRegex := regexp.MustCompile(`{[0-9]+}: *INSTALLED`)
	connectionEstablishedRegex := regexp.MustCompile(`[[0-9]+]: *ESTABLISHED`)

	if connectionEstablishedRegex.Match(statusLine) {
		if tunnelEstablishedRegex.Match(statusLine) {
			return tunnelInstalled
		} else {
			return connectionEstablished
		}
	} else if noMatchRegex.Match(statusLine) {
		return down
	}

	return unknown
}

func extractStringWithRegex(input string, regex string) string {
	re := regexp.MustCompile(regex)
	match := re.FindStringSubmatch(input)

	if len(match) >= 2 {
		return match[1]
	}

	return ""
}

func extractIntWithRegex(input string, regex string) int {
	re := regexp.MustCompile(regex)
	match := re.FindStringSubmatch(input)
	if len(match) >= 2 {
		i, err := strconv.Atoi(match[1])
		if err != nil {
			return -1
		}
		return i
	}

	return -1
}
