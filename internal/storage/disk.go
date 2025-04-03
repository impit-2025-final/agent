package storage

import (
	"agent/internal/domain"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type DiskStorage struct {
	baseDir string
}

func NewDiskStorage(baseDir string) (*DiskStorage, error) {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	return &DiskStorage{
		baseDir: baseDir,
	}, nil
}

func (s *DiskStorage) SaveDockerInfo(info *domain.DockerInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	filename := filepath.Join(s.baseDir, fmt.Sprintf("docker_info_%d.json", time.Now().Unix()))
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("error: %w", err)
	}

	s.cleanupOldFiles("docker_info_*.json", time.Hour)
	return nil
}

func (s *DiskStorage) SaveNetworkTraffic(traffic []domain.NetworkTraffic) error {
	data, err := json.Marshal(traffic)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	filename := filepath.Join(s.baseDir, fmt.Sprintf("network_traffic_%d.json", time.Now().Unix()))
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("error: %w", err)
	}

	s.cleanupOldFiles("network_traffic_*.json", time.Hour)
	return nil
}

func (s *DiskStorage) cleanupOldFiles(pattern string, maxAge time.Duration) {
	files, err := filepath.Glob(filepath.Join(s.baseDir, pattern))
	if err != nil {
		return
	}

	now := time.Now()
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		if now.Sub(info.ModTime()) > maxAge {
			os.Remove(file)
		}
	}
}
