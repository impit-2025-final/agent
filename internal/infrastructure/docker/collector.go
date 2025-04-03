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
	client  *client.Client
	network string
}

func NewCollector(network string) (*Collector, error) {
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
		client:  cli,
		network: network,
	}, nil
}

func (c *Collector) Collect(ctx context.Context) (*domain.DockerInfo, error) {
	containers, err := c.client.ContainerList(ctx, container.ListOptions{
		Size: false,
	})
	if err != nil {
		return nil, errors.Wrap(err, "error")
	}

	network, err := c.client.NetworkInspect(ctx, c.network, network.InspectOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "error %s", c.network)
	}

	containerInfos := make([]domain.ContainerInfo, 0, len(containers))
	for _, container := range containers {
		info := domain.ContainerInfo{
			ID:     container.ID[:12],
			Name:   container.Names[0][1:],
			Status: container.Status,
			Labels: container.Labels,
		}

		containerDetails, err := c.client.ContainerInspect(ctx, container.ID)
		if err != nil {
			log.Printf("error %s: %v", container.ID[:12], err)
			continue
		}

		if containerDetails.NetworkSettings != nil {
			if networkSettings, ok := containerDetails.NetworkSettings.Networks[c.network]; ok {
				info.IP = networkSettings.IPAddress
			}
		}

		containerInfos = append(containerInfos, info)
	}

	networkInfo := domain.NetworkInfo{
		Name:       network.Name,
		Subnet:     network.IPAM.Config[0].Subnet,
		Gateway:    network.IPAM.Config[0].Gateway,
		Containers: getContainerIDs(network.Containers),
	}

	return &domain.DockerInfo{
		Containers: containerInfos,
		Network:    networkInfo,
	}, nil
}

func getContainerIDs(containers map[string]network.EndpointResource) []string {
	ids := make([]string, 0, len(containers))
	for _, container := range containers {
		ids = append(ids, container.EndpointID[:12])
	}
	return ids
}
