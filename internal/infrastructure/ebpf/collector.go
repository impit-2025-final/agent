package ebpf

import (
	"agent/internal/domain"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Collector struct {
	program *ebpf.Program
	mapObj  *ebpf.Map
	links   []link.Link
}

func NewCollector() (*Collector, error) {
	spec, err := ebpf.LoadCollectionSpec("bpf/traffic_monitor.o")
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	var objs struct {
		TrafficMonitor *ebpf.Program `ebpf:"traffic_monitor"`
		TrafficMap     *ebpf.Map     `ebpf:"traffic_map"`
	}

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	return &Collector{
		program: objs.TrafficMonitor,
		mapObj:  objs.TrafficMap,
		links:   make([]link.Link, 0),
	}, nil
}

func (c *Collector) Collect(ctx context.Context) ([]domain.NetworkTraffic, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	for _, l := range c.links {
		l.Close()
	}
	c.links = c.links[:0]

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   c.program,
			Interface: iface.Index,
		})
		if err != nil {
			log.Printf("error %s: %v", iface.Name, err)
			continue
		}
		c.links = append(c.links, l)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	var traffic []domain.NetworkTraffic
	iter := c.mapObj.Iterate()
	var key, value struct {
		SrcIP   uint32
		DstIP   uint32
		Proto   uint8
		Bytes   uint64
		Packets uint64
	}

	for iter.Next(&key, &value) {
		traffic = append(traffic, domain.NetworkTraffic{
			SourceIP:      net.IPv4(byte(key.SrcIP>>24), byte(key.SrcIP>>16), byte(key.SrcIP>>8), byte(key.SrcIP)).String(),
			DestinationIP: net.IPv4(byte(key.DstIP>>24), byte(key.DstIP>>16), byte(key.DstIP>>8), byte(key.DstIP)).String(),
			Protocol:      getProtocolName(value.Proto),
			Bytes:         int64(value.Bytes),
			Packets:       int64(value.Packets),
		})
	}

	return traffic, nil
}

func (c *Collector) Close() error {
	for _, l := range c.links {
		if err := l.Close(); err != nil {
			return fmt.Errorf("error: %w", err)
		}
	}
	return nil
}

func getProtocolName(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return "Unknown"
	}
}
