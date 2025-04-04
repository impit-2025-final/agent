package storage

import (
	"agent/internal/domain"
	"strconv"
	"sync"
)

type MemoryStorage struct {
	mu             sync.RWMutex
	dockerInfo     *domain.DockerInfo
	networkTraffic map[string]domain.NetworkTraffic
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		networkTraffic: make(map[string]domain.NetworkTraffic),
	}
}

func (s *MemoryStorage) AddDockerInfo(info *domain.DockerInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dockerInfo = info
}

func (s *MemoryStorage) AddNetworkTraffic(traffic []domain.NetworkTraffic) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range traffic {
		key := t.SourceIP + t.DestinationIP + t.Protocol + t.Interface + strconv.Itoa(int(t.SrcPort)) + strconv.Itoa(int(t.DstPort))
		if existing, exists := s.networkTraffic[key]; exists {
			existing.Bytes += t.Bytes
			existing.Packets += t.Packets
			existing.LastUpdate = t.LastUpdate
			existing.RealTime = t.RealTime
			existing.Processed = t.Processed
			s.networkTraffic[key] = existing
		} else {
			s.networkTraffic[key] = t
		}
	}
}

func (s *MemoryStorage) GetDockerInfo() *domain.DockerInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dockerInfo
}

func (s *MemoryStorage) GetNetworkTraffic() []domain.NetworkTraffic {
	s.mu.RLock()
	defer s.mu.RUnlock()

	traffic := make([]domain.NetworkTraffic, 0, len(s.networkTraffic))
	for _, t := range s.networkTraffic {
		traffic = append(traffic, t)
	}
	return traffic
}

func (s *MemoryStorage) DeleteNetworkTraffic(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.networkTraffic, key)
}

func (s *MemoryStorage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dockerInfo = nil
	s.networkTraffic = make(map[string]domain.NetworkTraffic)
}
