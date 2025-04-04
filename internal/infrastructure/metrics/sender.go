package metrics

import (
	"agent/internal/domain"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Sender struct {
	client     *http.Client
	serviceURL string
	token      string
}

func NewSender(serviceURL string, token string) *Sender {
	return &Sender{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		serviceURL: serviceURL,
		token:      token,
	}
}

func (s *Sender) SendDockerInfo(ctx context.Context, info *domain.DockerInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	req, err := s.createRequest(ctx, "POST", fmt.Sprintf("%s/docker-info", s.serviceURL), data)
	if err != nil {
		return err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error: %d", resp.StatusCode)
	}

	return nil
}

func (s *Sender) SendNetworkTraffic(ctx context.Context, traffic []domain.NetworkTraffic) error {
	data, err := json.Marshal(traffic)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	req, err := s.createRequest(ctx, "POST", fmt.Sprintf("%s/network-traffic", s.serviceURL), data)
	if err != nil {
		return err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error %d", resp.StatusCode)
	}

	return nil
}

func (s *Sender) createRequest(ctx context.Context, method, url string, data []byte) (*http.Request, error) {
	var body io.Reader
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", s.token)
	return req, nil
}
