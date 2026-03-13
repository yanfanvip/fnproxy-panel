package utils

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"fnproxy/config"
	"fnproxy/models"

	"github.com/google/uuid"
	gnet "github.com/shirou/gopsutil/v3/net"
)

const (
	networkSampleInterval = time.Minute
	networkRetention      = 24 * time.Hour
	statsRateWindow       = time.Minute
	defaultLogLimit       = 200
)

type trafficEvent struct {
	Timestamp time.Time
	BytesIn   uint64
	BytesOut  uint64
}

type runtimeBucket struct {
	RequestCount      uint64
	ActiveConnections int64
	BytesInTotal      uint64
	BytesOutTotal     uint64
	LastSeenAt        time.Time
	Recent            []trafficEvent
}

// Monitor 运行时监控信息
type Monitor struct {
	mu              sync.RWMutex
	listenerStats   map[string]*runtimeBucket
	serviceStats    map[string]*runtimeBucket
	lastNetCounter  *gnet.IOCountersStat
	lastNetSampleAt time.Time
	store           *monitorStore
}

var (
	monitorOnce sync.Once
	monitorInst *Monitor
)

// GetMonitor 获取监控单例
func GetMonitor() *Monitor {
	monitorOnce.Do(func() {
		store, _ := newMonitorStore(config.RuntimeMonitorCachePath())
		monitorInst = &Monitor{
			listenerStats: make(map[string]*runtimeBucket),
			serviceStats:  make(map[string]*runtimeBucket),
			store:         store,
		}
		monitorInst.bootstrapNetworkSampler()
	})
	return monitorInst
}

func (m *Monitor) bootstrapNetworkSampler() {
	m.sampleNetwork()
	go func() {
		ticker := time.NewTicker(networkSampleInterval)
		defer ticker.Stop()
		for range ticker.C {
			m.sampleNetwork()
		}
	}()
}

func (m *Monitor) sampleNetwork() {
	netIO, err := gnet.IOCounters(false)
	if err != nil || len(netIO) == 0 {
		return
	}

	now := time.Now()
	current := netIO[0]
	var sample *models.NetworkSample

	m.mu.Lock()
	if m.lastNetCounter != nil && !m.lastNetSampleAt.IsZero() {
		elapsed := now.Sub(m.lastNetSampleAt).Seconds()
		if elapsed > 0 {
			var recvDelta uint64
			var sentDelta uint64
			if current.BytesRecv >= m.lastNetCounter.BytesRecv {
				recvDelta = current.BytesRecv - m.lastNetCounter.BytesRecv
			}
			if current.BytesSent >= m.lastNetCounter.BytesSent {
				sentDelta = current.BytesSent - m.lastNetCounter.BytesSent
			}

			builtSample := models.NetworkSample{
				Timestamp: now,
				InRate:    float64(recvDelta) / elapsed,
				OutRate:   float64(sentDelta) / elapsed,
			}
			sample = &builtSample
		}
	}

	m.lastNetCounter = &current
	m.lastNetSampleAt = now
	m.mu.Unlock()

	if sample != nil {
		_ = m.store.appendNetworkSample(*sample)
	}
}

func (m *Monitor) beginRequest(listener models.PortListener, service models.ServiceConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	listenerBucket := m.ensureListenerBucketLocked(listener.ID)
	serviceBucket := m.ensureServiceBucketLocked(service.ID)
	listenerBucket.ActiveConnections++
	serviceBucket.ActiveConnections++
	listenerBucket.LastSeenAt = now
	serviceBucket.LastSeenAt = now
}

// RecordRequest 记录一次服务请求
func (m *Monitor) RecordRequest(listener models.PortListener, service models.ServiceConfig, r *http.Request, statusCode int, bytesOut uint64, duration time.Duration, username string, writeLog bool) {
	m.mu.Lock()
	now := time.Now()
	bytesIn := requestBytesIn(r)
	listenerBucket := m.ensureListenerBucketLocked(listener.ID)
	serviceBucket := m.ensureServiceBucketLocked(service.ID)
	var logEntry *models.AccessLogEntry

	listenerBucket.ActiveConnections--
	if listenerBucket.ActiveConnections < 0 {
		listenerBucket.ActiveConnections = 0
	}
	serviceBucket.ActiveConnections--
	if serviceBucket.ActiveConnections < 0 {
		serviceBucket.ActiveConnections = 0
	}

	listenerBucket.RequestCount++
	serviceBucket.RequestCount++
	listenerBucket.BytesInTotal += bytesIn
	listenerBucket.BytesOutTotal += bytesOut
	serviceBucket.BytesInTotal += bytesIn
	serviceBucket.BytesOutTotal += bytesOut
	listenerBucket.LastSeenAt = now
	serviceBucket.LastSeenAt = now

	event := trafficEvent{Timestamp: now, BytesIn: bytesIn, BytesOut: bytesOut}
	listenerBucket.Recent = append(listenerBucket.Recent, event)
	serviceBucket.Recent = append(serviceBucket.Recent, event)
	m.pruneRecentLocked(listenerBucket, now)
	m.pruneRecentLocked(serviceBucket, now)

	if writeLog {
		entry := models.AccessLogEntry{
			ID:           uuid.NewString(),
			Timestamp:    now,
			ListenerID:   listener.ID,
			ListenerPort: listener.Port,
			ServiceID:    service.ID,
			ServiceName:  service.Name,
			Host:         r.Host,
			Method:       r.Method,
			Path:         r.URL.RequestURI(),
			StatusCode:   statusCode,
			DurationMS:   duration.Milliseconds(),
			BytesIn:      bytesIn,
			BytesOut:     bytesOut,
			RemoteAddr:   r.RemoteAddr,
			Username:     username,
		}
		logEntry = &entry
	}
	m.mu.Unlock()

	if logEntry != nil {
		_ = m.store.appendAccessLog(*logEntry)
	}
}

func (m *Monitor) BeginRequest(listener models.PortListener, service models.ServiceConfig) {
	m.beginRequest(listener, service)
}

func requestBytesIn(r *http.Request) uint64 {
	if r.ContentLength > 0 {
		return uint64(r.ContentLength)
	}
	return 0
}

func (m *Monitor) ensureListenerBucketLocked(id string) *runtimeBucket {
	bucket, ok := m.listenerStats[id]
	if !ok {
		bucket = &runtimeBucket{}
		m.listenerStats[id] = bucket
	}
	return bucket
}

func (m *Monitor) ensureServiceBucketLocked(id string) *runtimeBucket {
	bucket, ok := m.serviceStats[id]
	if !ok {
		bucket = &runtimeBucket{}
		m.serviceStats[id] = bucket
	}
	return bucket
}

func (m *Monitor) pruneRecentLocked(bucket *runtimeBucket, now time.Time) {
	cutoff := now.Add(-statsRateWindow)
	idx := 0
	for idx < len(bucket.Recent) && bucket.Recent[idx].Timestamp.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		bucket.Recent = append([]trafficEvent{}, bucket.Recent[idx:]...)
	}
}

func buildRuntimeStats(bucket *runtimeBucket) models.RuntimeStats {
	stats := models.RuntimeStats{}
	if bucket == nil {
		return stats
	}
	stats.RequestCount = bucket.RequestCount
	stats.ActiveConnections = bucket.ActiveConnections
	stats.BytesInTotal = bucket.BytesInTotal
	stats.BytesOutTotal = bucket.BytesOutTotal
	stats.LastSeenAt = bucket.LastSeenAt

	var inWindow uint64
	var outWindow uint64
	for _, event := range bucket.Recent {
		inWindow += event.BytesIn
		outWindow += event.BytesOut
	}
	stats.BytesInRate = float64(inWindow) / statsRateWindow.Seconds()
	stats.BytesOutRate = float64(outWindow) / statsRateWindow.Seconds()
	return stats
}

// GetListenerStats 获取所有监听统计
func (m *Monitor) GetListenerStats() []models.ListenerRuntimeStats {
	cfg := config.GetManager().GetConfig()
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]models.ListenerRuntimeStats, 0, len(cfg.Listeners))
	for _, listener := range cfg.Listeners {
		stats := buildRuntimeStats(m.listenerStats[listener.ID])
		result = append(result, models.ListenerRuntimeStats{
			ListenerID:   listener.ID,
			Port:         listener.Port,
			RuntimeStats: stats,
		})
	}
	return result
}

// GetListenerStatsByID 获取单个监听统计
func (m *Monitor) GetListenerStatsByID(listenerID string) models.ListenerRuntimeStats {
	listener := config.GetManager().GetListener(listenerID)
	stats := models.ListenerRuntimeStats{ListenerID: listenerID}
	if listener != nil {
		stats.Port = listener.Port
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	stats.RuntimeStats = buildRuntimeStats(m.listenerStats[listenerID])
	return stats
}

// GetServiceStatsByPort 获取端口下服务统计
func (m *Monitor) GetServiceStatsByPort(portID string) []models.ServiceRuntimeStats {
	services := config.GetManager().GetServicesByPort(portID)
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]models.ServiceRuntimeStats, 0, len(services))
	for _, service := range services {
		stats := buildRuntimeStats(m.serviceStats[service.ID])
		result = append(result, models.ServiceRuntimeStats{
			ServiceID:    service.ID,
			ListenerID:   service.PortID,
			ServiceName:  service.Name,
			Domain:       service.Domain,
			Type:         service.Type,
			RuntimeStats: stats,
		})
	}
	return result
}

// GetServiceStatsByID 获取服务统计
func (m *Monitor) GetServiceStatsByID(serviceID string) models.ServiceRuntimeStats {
	service := config.GetManager().GetService(serviceID)
	stats := models.ServiceRuntimeStats{ServiceID: serviceID}
	if service != nil {
		stats.ListenerID = service.PortID
		stats.ServiceName = service.Name
		stats.Domain = service.Domain
		stats.Type = service.Type
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	stats.RuntimeStats = buildRuntimeStats(m.serviceStats[serviceID])
	return stats
}

// GetNetworkHistory24h 获取24小时内每10分钟平均网络流量
func (m *Monitor) GetNetworkHistory24h() []models.NetworkSample {
	now := time.Now()
	samples, err := m.store.listNetworkSamplesSince(now.Add(-24 * time.Hour))
	if err != nil {
		samples = nil
	}
	start := now.Add(-24 * time.Hour).Truncate(10 * time.Minute)
	result := make([]models.NetworkSample, 0, 144)

	for bucketStart := start; bucketStart.Before(now); bucketStart = bucketStart.Add(10 * time.Minute) {
		bucketEnd := bucketStart.Add(10 * time.Minute)
		var inSum float64
		var outSum float64
		var count float64
		for _, sample := range samples {
			if !sample.Timestamp.Before(bucketStart) && sample.Timestamp.Before(bucketEnd) {
				inSum += sample.InRate
				outSum += sample.OutRate
				count++
			}
		}

		point := models.NetworkSample{Timestamp: bucketStart}
		if count > 0 {
			point.InRate = inSum / count
			point.OutRate = outSum / count
		}
		result = append(result, point)
	}

	return result
}

// GetListenerLogs 获取监听日志
func (m *Monitor) GetListenerLogs(listenerID string, limit int) []models.AccessLogEntry {
	return m.filterLogs(func(entry models.AccessLogEntry) bool {
		return entry.ListenerID == listenerID
	}, limit)
}

// GetServiceLogs 获取服务日志
func (m *Monitor) GetServiceLogs(serviceID string, limit int) []models.AccessLogEntry {
	return m.filterLogs(func(entry models.AccessLogEntry) bool {
		return entry.ServiceID == serviceID
	}, limit)
}

func (m *Monitor) filterLogs(match func(models.AccessLogEntry) bool, limit int) []models.AccessLogEntry {
	if limit <= 0 {
		limit = defaultLogLimit
	}
	result, err := m.store.listAccessLogs(limit, match)
	if err != nil {
		return []models.AccessLogEntry{}
	}
	return result
}

// FormatRate 格式化速率
func FormatRate(rate float64) string {
	return fmt.Sprintf("%s/s", FormatBytes(uint64(rate)))
}
