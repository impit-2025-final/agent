package docker

import (
	"agent/internal/domain"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
)

type Collector struct {
	client *client.Client
}

func NewCollector() (*Collector, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := cli.Ping(ctx); err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	return &Collector{
		client: cli,
	}, nil
}

func (c *Collector) Collect(ctx context.Context) (*domain.DockerInfo, error) {
	containers, err := c.client.ContainerList(ctx, container.ListOptions{
		Size: false,
	})
	if err != nil {
		return nil, errors.Wrap(err, "error")
	}

	networks, err := c.client.NetworkList(ctx, network.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "error fetching networks")
	}

	containerInfos := make([]domain.ContainerInfo, 0, len(containers))
	for _, container := range containers {
		info := domain.ContainerInfo{
			ContainerID:   container.ID[:12],
			ContainerName: container.Names[0][1:],
			Status:        container.Status,
			Labels:        container.Labels,
		}

		containerDetails, err := c.client.ContainerInspect(ctx, container.ID)
		if err != nil {
			log.Printf("error %s: %v", container.ID[:12], err)
			continue
		}

		for _, network := range containerDetails.NetworkSettings.Networks {
			info.IP = network.IPAddress
		}

		containerInfos = append(containerInfos, info)
	}

	networkInfos := make([]domain.NetworkInfo, 0, len(networks))
	for _, network := range networks {
		if len(network.IPAM.Config) == 0 {
			continue
		}
		networkInfo := domain.NetworkInfo{
			Name:       network.Name,
			Subnet:     network.IPAM.Config[0].Subnet,
			Gateway:    network.IPAM.Config[0].Gateway,
			Containers: getContainerIDs(network.Containers),
		}
		networkInfos = append(networkInfos, networkInfo)
	}

	return &domain.DockerInfo{
		Containers: containerInfos,
		Networks:   networkInfos,
	}, nil
}

func getContainerIDs(containers map[string]network.EndpointResource) []string {
	ids := make([]string, 0, len(containers))
	for _, container := range containers {
		ids = append(ids, container.EndpointID[:12])
	}
	return ids
}
