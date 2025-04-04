package storage

import (
	"agent/internal/domain"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type QueueStorage struct {
	baseDir string
	memory  *MemoryStorage
}

func NewQueueStorage(baseDir string) (*QueueStorage, error) {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	return &QueueStorage{
		baseDir: baseDir,
		memory:  NewMemoryStorage(),
	}, nil
}

func (s *QueueStorage) DeleteNetworkTraffic(key string) {
	s.memory.DeleteNetworkTraffic(key)
}

func (s *QueueStorage) AddDockerInfo(info *domain.DockerInfo) {
	if info == nil {
		return
	}

	if len(info.Containers) == 0 {
		return
	}

	s.memory.AddDockerInfo(info)
}

func (s *QueueStorage) AddNetworkTraffic(traffic []domain.NetworkTraffic) {
	if len(traffic) == 0 {
		return
	}

	s.memory.AddNetworkTraffic(traffic)
}

func (s *QueueStorage) GetDockerInfoBatch() ([]*domain.DockerInfo, error) {
	info := s.memory.GetDockerInfo()
	if info == nil {
		return nil, nil
	}
	return []*domain.DockerInfo{info}, nil
}

func (s *QueueStorage) GetNetworkTrafficBatch() ([]domain.NetworkTraffic, error) {
	return s.memory.GetNetworkTraffic(), nil
}

func (s *QueueStorage) Cleanup(maxAge time.Duration) error {
	files, err := filepath.Glob(filepath.Join(s.baseDir, "*.json"))
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	now := time.Now()
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		if now.Sub(info.ModTime()) > maxAge {
			if err := os.Remove(file); err != nil {
				return fmt.Errorf("error %s: %w", file, err)
			}
		}
	}

	return nil
}
