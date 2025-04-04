package ebpf

import (
	"agent/internal/domain"
	"agent/internal/infrastructure/docker"
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Collector struct {
	program         *ebpf.Program
	mapObj          *ebpf.Map
	links           []link.Link
	dockerCollector *docker.Collector
	containerCache  map[string]domain.ContainerInfo
	lastUpdate      time.Time
}

func NewCollector(dockerCollector *docker.Collector) (*Collector, error) {
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

	dockerColl, err := docker.NewCollector()
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	return &Collector{
		program:         objs.TrafficMonitor,
		mapObj:          objs.TrafficMap,
		links:           make([]link.Link, 0),
		dockerCollector: dockerColl,
		containerCache:  make(map[string]domain.ContainerInfo),
		lastUpdate:      time.Time{},
	}, nil
}

func (c *Collector) updateContainerCache(ctx context.Context) error {
	if time.Since(c.lastUpdate) < 5*time.Second {
		return nil
	}

	dockerInfo, err := c.dockerCollector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	c.containerCache = make(map[string]domain.ContainerInfo)

	for _, container := range dockerInfo.Containers {
		if container.IP != "" {
			c.containerCache[container.IP] = container
		}
	}

	c.lastUpdate = time.Now()
	return nil
}

func (c *Collector) Collect(ctx context.Context) ([]domain.NetworkTraffic, error) {
	if err := c.updateContainerCache(ctx); err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("error getting interfaces: %w", err)
	}

	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		addrStrings := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			addrStrings = append(addrStrings, addr.String())
		}
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

		var l link.Link
		var attachErr error

		modes := []struct {
			name  string
			flags link.XDPAttachFlags
		}{
			{"XDPGenericMode", link.XDPGenericMode},
			{"XDPDriverMode", link.XDPDriverMode},
		}

		attached := false
		for _, mode := range modes {
			if strings.HasPrefix(iface.Name, "docker") {
				continue
			}

			l, attachErr = link.AttachXDP(link.XDPOptions{
				Program:   c.program,
				Interface: iface.Index,
				Flags:     mode.flags,
			})

			if attachErr == nil {
				c.links = append(c.links, l)
				attached = true
				break
			}
		}

		if !attached {
			return nil, fmt.Errorf("error: %w", attachErr)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	var traffic []domain.NetworkTraffic
	iter := c.mapObj.Iterate()
	var key struct {
		SrcIP   uint32
		DstIP   uint32
		Proto   uint8
		IfIndex uint32
	}

	var value struct {
		Bytes   uint64
		Packets uint64
	}

	var entriesCount int

	for iter.Next(&key, &value) {
		entriesCount++
		iface, err := net.InterfaceByIndex(int(key.IfIndex))
		if err != nil {
			return nil, fmt.Errorf("error: %w", err)
		}

		srcIP := net.IPv4(byte(key.SrcIP), byte(key.SrcIP>>8), byte(key.SrcIP>>16), byte(key.SrcIP>>24)).String()
		dstIP := net.IPv4(byte(key.DstIP), byte(key.DstIP>>8), byte(key.DstIP>>16), byte(key.DstIP>>24)).String()

		var containerID, containerName string
		if container, found := c.containerCache[srcIP]; found {
			containerID = container.ID
			containerName = container.Name
		} else if container, found := c.containerCache[dstIP]; found {
			containerID = container.ID
			containerName = container.Name
		}

		if containerID == "" && containerName == "" {
			continue
		}

		traffic = append(traffic, domain.NetworkTraffic{
			SourceIP:      srcIP,
			DestinationIP: dstIP,
			Protocol:      getProtocolName(key.Proto),
			Bytes:         int64(value.Bytes),
			Packets:       int64(value.Packets),
			ContainerID:   containerID,
			ContainerName: containerName,
			Interface:     iface.Name,
		})
	}

	return traffic, nil
}

func (c *Collector) Close() error {
	for _, l := range c.links {
		if err := l.Close(); err != nil {
			return fmt.Errorf("error closing link: %w", err)
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
		return fmt.Sprintf("Unknown(%d)", proto)
	}
}
