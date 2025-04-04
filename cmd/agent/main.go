package main

import (
	"agent/internal/config"
	"agent/internal/domain"
	"agent/internal/infrastructure/docker"
	"agent/internal/infrastructure/ebpf"
	"agent/internal/infrastructure/metrics"
	"agent/internal/storage"
	"context"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

func main() {
	runtime.GOMAXPROCS(1)
	runtime.SetCPUProfileRate(0)
	runtime.SetBlockProfileRate(0)
	runtime.SetMutexProfileFraction(0)

	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	storageDir := filepath.Join("./", "data")
	queueStorage, err := storage.NewQueueStorage(storageDir)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	dockerCollector, err := docker.NewCollector()
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	networkCollector, err := ebpf.NewCollector(dockerCollector, queueStorage)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	metricsSender := metrics.NewSender(cfg.Service.URL, cfg.Service.Token)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})

	go func() {
		defer close(done)

		dockerChan := make(chan *domain.DockerInfo, 10)
		networkChan := make(chan []domain.NetworkTraffic, 10)

		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if len(dockerChan) == cap(dockerChan) || len(networkChan) == cap(networkChan) {
						continue
					}

					collectCtx, collectCancel := context.WithTimeout(ctx, 2*time.Second)

					dockerInfo, err := dockerCollector.Collect(collectCtx)
					if err != nil {
						log.Printf("error: %v", err)
						collectCancel()
						continue
					}

					// fmt.Println(dockerInfo)

					select {
					case dockerChan <- dockerInfo:
					default:
						log.Printf("full docker")
					}

					networkTraffic, err := networkCollector.Collect(collectCtx)
					if err != nil {
						log.Printf("error: %v", err)
						collectCancel()
						continue
					}
					// fmt.Println(networkTraffic)

					select {
					case networkChan <- networkTraffic:
					default:
						log.Printf("full network")
					}

					collectCancel()
				}
			}
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case dockerInfo := <-dockerChan:
				queueStorage.AddDockerInfo(dockerInfo)
			case networkTraffic := <-networkChan:
				queueStorage.AddNetworkTraffic(networkTraffic)
			}
		}
	}()

	go func() {
		sendTicker := time.NewTicker(time.Duration(cfg.Service.UpdateInterval) * time.Second)
		defer sendTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-sendTicker.C:
				sendCtx, sendCancel := context.WithTimeout(ctx, 30*time.Second)

				dockerBatch, err := queueStorage.GetDockerInfoBatch()
				if err != nil {
					log.Printf("error: %v", err)
					sendCancel()
					continue
				}

				networkBatch, err := queueStorage.GetNetworkTrafficBatch()
				if err != nil {
					log.Printf("error: %v", err)
					sendCancel()
					continue
				}

				if len(dockerBatch) > 0 {
					if err := metricsSender.SendDockerInfo(sendCtx, dockerBatch[0]); err != nil {
						log.Printf("error: %v", err)
					}
				}

				if len(networkBatch) > 0 {
					if err := metricsSender.SendNetworkTraffic(sendCtx, networkBatch); err != nil {
						log.Printf("error: %v", err)
					}

				}

				ips, err := net.InterfaceAddrs()
				if err != nil {
					log.Printf("error: %v", err)
				}

				ipsString := []string{}
				for _, ip := range ips {
					addr, err := netip.ParseAddr(ip.String())
					if err != nil {
						log.Printf("error: %v", err)
					}
					if addr.IsGlobalUnicast() {
						ipsString = append(ipsString, ip.String())
					}
				}

				metricsSender.SendNodeInfo(sendCtx, &domain.NodeInfo{
					Hostname: &cfg.Node.Name,
					Ips:      ipsString,
				})

				sendCancel()

				if err := queueStorage.Cleanup(); err != nil {
					log.Printf("error: %v", err)
				}

				runtime.GC()
			}
		}
	}()

	<-sigChan
	log.Println("Shutting down...")

	cancel()
	<-done
}
