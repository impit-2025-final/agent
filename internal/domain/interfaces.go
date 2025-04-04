package domain

import (
	"context"
)

type DockerInfo struct {
	Containers []ContainerInfo
	Networks   []NetworkInfo
}

type ContainerInfo struct {
	ID            string
	Name          string
	IP            string
	Status        string
	Labels        map[string]string
	AdditionalIPs []string
}

type NetworkInfo struct {
	Name       string
	Subnet     string
	Gateway    string
	Containers []string
}

type NetworkTraffic struct {
	SourceIP      string
	DestinationIP string
	Protocol      string
	Interface     string
	Bytes         int64
	Packets       int64
	ContainerID   string
	ContainerName string
	SrcPort       uint16
	DstPort       uint16
}

type DockerCollector interface {
	Collect(ctx context.Context) (*DockerInfo, error)
}

type NetworkCollector interface {
	Collect(ctx context.Context) ([]NetworkTraffic, error)
}

type MetricsSender interface {
	SendDockerInfo(ctx context.Context, info *DockerInfo) error
	SendNetworkTraffic(ctx context.Context, traffic []NetworkTraffic) error
}
