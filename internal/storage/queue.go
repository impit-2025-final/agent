package storage

import (
	"agent/internal/domain"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type QueueStorage struct {
	baseDir string
}

func NewQueueStorage(baseDir string) (*QueueStorage, error) {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	return &QueueStorage{
		baseDir: baseDir,
	}, nil
}

func (s *QueueStorage) AddDockerInfo(info *domain.DockerInfo) error {
	if info == nil {
		return nil
	}

	if len(info.Containers) == 0 {
		return nil
	}

	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	filename := filepath.Join(s.baseDir, fmt.Sprintf("docker_info_%d.json", time.Now().UnixNano()))
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("error: %w", err)
	}
	return nil
}

func (s *QueueStorage) AddNetworkTraffic(traffic []domain.NetworkTraffic) error {
	if len(traffic) == 0 {
		return nil
	}

	data, err := json.Marshal(traffic)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	filename := filepath.Join(s.baseDir, fmt.Sprintf("network_traffic_%d.json", time.Now().UnixNano()))
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("error: %w", err)
	}
	return nil
}

func (s *QueueStorage) GetDockerInfoBatch() ([]*domain.DockerInfo, error) {
	files, err := filepath.Glob(filepath.Join(s.baseDir, "docker_info_*.json"))
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	sort.Strings(files)
	var batch []*domain.DockerInfo

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var info domain.DockerInfo
		if err := json.Unmarshal(data, &info); err != nil {
			continue
		}

		batch = append(batch, &info)
		os.Remove(file)
	}

	return batch, nil
}

func (s *QueueStorage) CheckNetworkTrafficeDuplicate(traffic []domain.NetworkTraffic) (exist bool, err error) {

	files, err := filepath.Glob(filepath.Join(s.baseDir, "network_traffic_*.json"))
	if err != nil {
		return false, fmt.Errorf("error: %w", err)
	}

	sort.Strings(files)

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var traffic []domain.NetworkTraffic
		if err := json.Unmarshal(data, &traffic); err != nil {
			continue
		}

		// for _, t := range traffic {
		// 	if t.PayloadHash == traffic[0].PayloadHash {
		// 		return true, nil
		// 	}
		// }
	}
	return false, nil
}

func (s *QueueStorage) GetNetworkTrafficBatch() ([]domain.NetworkTraffic, error) {
	files, err := filepath.Glob(filepath.Join(s.baseDir, "network_traffic_*.json"))
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	sort.Strings(files)
	var batch []domain.NetworkTraffic

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var traffic []domain.NetworkTraffic
		if err := json.Unmarshal(data, &traffic); err != nil {
			continue
		}

		batch = append(batch, traffic...)
		os.Remove(file)
	}

	return batch, nil
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
