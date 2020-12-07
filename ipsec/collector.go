package ipsec

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	metricUp         = prometheus.NewDesc("ipsec_up", "value indicating a successful scrape", []string{"tunnel", "user"}, nil)
	metricStatus     = prometheus.NewDesc("ipsec_tunnel_status", "ipsec status value", []string{"tunnel", "user"}, nil)
	metricBytesIn    = prometheus.NewDesc("ipsec_in_bytes", "received bytes per tunnel", []string{"tunnel", "user"}, nil)
	metricBytesOut   = prometheus.NewDesc("ipsec_out_bytes", "sent bytes per tunnel", []string{"tunnel", "user"}, nil)
	metricPacketsIn  = prometheus.NewDesc("ipsec_in_packets", "received packets per tunnel", []string{"tunnel", "user"}, nil)
	metricPacketsOut = prometheus.NewDesc("ipsec_out_packets", "sent packets per tunnel", []string{"tunnel", "user"}, nil)
)

func NewCollector(configurations ...*Configuration) *Collector {
	return &Collector{
		configurations: configurations,
	}
}

type Collector struct {
	configurations []*Configuration
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metricUp
	ch <- metricStatus
	ch <- metricBytesIn
	ch <- metricBytesOut
	ch <- metricPacketsIn
	ch <- metricPacketsOut
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	for _, configuration := range c.configurations {
		for _, tunnelconfig := range configuration.tunnel {
			status := queryUserStatus(tunnelconfig, &cliStatusProvider{})
			for tunnel, tunnelStatus := range status {
				for user, userdata := range tunnelStatus {
					fmt.Println("tunnel name: ", tunnel, "\nStatus: ", userdata, "\n")
					ch <- prometheus.MustNewConstMetric(metricUp, prometheus.GaugeValue, c.toFloat64(userdata.up), tunnel, user)
					ch <- prometheus.MustNewConstMetric(metricStatus, prometheus.GaugeValue, float64(userdata.status), tunnel, user)
					ch <- prometheus.MustNewConstMetric(metricBytesIn, prometheus.CounterValue, float64(userdata.ubytesIn), tunnel, user)
					ch <- prometheus.MustNewConstMetric(metricBytesOut, prometheus.CounterValue, float64(userdata.ubytesOut), tunnel, user)
					ch <- prometheus.MustNewConstMetric(metricPacketsIn, prometheus.CounterValue, float64(userdata.upacketsIn), tunnel, user)
					ch <- prometheus.MustNewConstMetric(metricPacketsOut, prometheus.CounterValue, float64(userdata.upacketsOut), tunnel, user)
				}
			}
		}
	}
}

func (c *Collector) toFloat64(value bool) float64 {
	if value {
		return 1
	}

	return 0
}
