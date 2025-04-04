package domain

import (
	"context"
)

type DockerInfo struct {
	Containers []ContainerInfo `json:"containers"`
	Networks   []NetworkInfo   `json:"networks"`
}

type ContainerInfo struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	IP            string            `json:"ip"`
	Status        string            `json:"status"`
	Labels        map[string]string `json:"labels"`
	AdditionalIPs []string          `json:"additional_ips"`
}

type NetworkInfo struct {
	Name       string   `json:"name"`
	Subnet     string   `json:"subnet"`
	Gateway    string   `json:"gateway"`
	Containers []string `json:"containers"`
}

type NetworkTraffic struct {
	SourceIP      string `json:"source_ip"`
	DestinationIP string `json:"destination_ip"`
	Protocol      string `json:"protocol"`
	Interface     string `json:"interface"`
	Bytes         int64  `json:"bytes"`
	Packets       int64  `json:"packets"`
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	SrcPort       uint16 `json:"src_port"`
	DstPort       uint16 `json:"dst_port"`
	LastUpdate    int64  `json:"last_update"`
	RealTime      int64  `json:"real_time"`
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
