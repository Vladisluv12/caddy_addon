package forwardproxy

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type userStats struct {
	rxBytes   uint64
	txBytes   uint64
	connCount int64
}

type userStatsJSON struct {
	RxBytes   uint64 `json:"rx"`
	TxBytes   uint64 `json:"tx"`
	ConnCount int64  `json:"conns"`
}

type TrafficSnapshot struct {
	Users     map[string]userStatsJSON `json:"users"`
	UpdatedAt int64                    `json:"updated_at"`
}

func (u *userStats) snapshot() userStatsJSON {
	return userStatsJSON{
		RxBytes:   atomic.LoadUint64(&u.rxBytes),
		TxBytes:   atomic.LoadUint64(&u.txBytes),
		ConnCount: atomic.LoadInt64(&u.connCount),
	}
}

type trafficState struct {
	mu       sync.RWMutex
	data     map[string]*userStats
	file     string
	log      *zap.Logger
	cancel   context.CancelFunc
	initOnce sync.Once
}

var globalTraffic trafficState

func InitTraffic(filePath string, logger *zap.Logger) {
	globalTraffic.initOnce.Do(func() {
		globalTraffic.log = logger
	})
	globalTraffic.mu.Lock()
	defer globalTraffic.mu.Unlock()

	if globalTraffic.cancel != nil {
		globalTraffic.cancel()
	}

	globalTraffic.file = filePath
	if logger != nil {
		globalTraffic.log = logger
	}

	globalTraffic.restoreFromFile()

	ctx, cancel := context.WithCancel(context.Background())
	globalTraffic.cancel = cancel
	go globalTraffic.periodicFlush(ctx)

	if globalTraffic.log != nil {
		globalTraffic.log.Info("per-user traffic counting enabled",
			zap.String("file", filePath))
	}
}

func (s *trafficState) restoreFromFile() {
	if s.file == "" {
		return
	}
	data, err := os.ReadFile(s.file)
	if err != nil {
		return
	}
	var snap TrafficSnapshot
	if json.Unmarshal(data, &snap) != nil {
		return
	}
	s.data = make(map[string]*userStats, len(snap.Users))
	for user, st := range snap.Users {
		us := &userStats{}
		atomic.StoreUint64(&us.rxBytes, st.RxBytes)
		atomic.StoreUint64(&us.txBytes, st.TxBytes)
		s.data[user] = us
	}
	if s.log != nil && len(s.data) > 0 {
		s.log.Info("restored per-user traffic counters", zap.Int("users", len(s.data)))
	}
}

func addTraffic(user string, rx, tx uint64) {
	if user == "" {
		return
	}
	s := &globalTraffic
	s.mu.RLock()
	u := s.data[user]
	s.mu.RUnlock()
	if u == nil {
		s.mu.Lock()
		u = s.data[user]
		if u == nil {
			u = &userStats{}
			s.data[user] = u
		}
		s.mu.Unlock()
	}
	if rx > 0 {
		atomic.AddUint64(&u.rxBytes, rx)
	}
	if tx > 0 {
		atomic.AddUint64(&u.txBytes, tx)
	}
}

func incConn(user string) {
	if user == "" {
		return
	}
	s := &globalTraffic
	s.mu.RLock()
	u := s.data[user]
	s.mu.RUnlock()
	if u == nil {
		s.mu.Lock()
		u = s.data[user]
		if u == nil {
			u = &userStats{}
			s.data[user] = u
		}
		s.mu.Unlock()
	}
	atomic.AddInt64(&u.connCount, 1)
}

func decConn(user string) {
	if user == "" {
		return
	}
	s := &globalTraffic
	s.mu.RLock()
	u := s.data[user]
	s.mu.RUnlock()
	if u != nil {
		atomic.AddInt64(&u.connCount, -1)
	}
}

func GetSnapshot() TrafficSnapshot {
	s := &globalTraffic
	s.mu.RLock()
	users := make(map[string]userStatsJSON, len(s.data))
	for k, v := range s.data {
		users[k] = v.snapshot()
	}
	s.mu.RUnlock()
	return TrafficSnapshot{
		Users:     users,
		UpdatedAt: time.Now().Unix(),
	}
}

func (s *trafficState) pruneStaleLocked() {
	for user, st := range s.data {
		if atomic.LoadInt64(&st.connCount) <= 0 &&
			atomic.LoadUint64(&st.rxBytes) == 0 &&
			atomic.LoadUint64(&st.txBytes) == 0 {
			delete(s.data, user)
		}
	}
}

func (s *trafficState) periodicFlush(ctx context.Context) {
	if s.file == "" {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			s.pruneStaleLocked()
			users := make(map[string]userStatsJSON, len(s.data))
			for k, v := range s.data {
				users[k] = v.snapshot()
			}
			s.mu.Unlock()

			snap := TrafficSnapshot{
				Users:     users,
				UpdatedAt: time.Now().Unix(),
			}
			data, err := json.Marshal(snap)
			if err != nil {
				if s.log != nil {
					s.log.Warn("traffic marshal error", zap.Error(err))
				}
				continue
			}
			tmp := s.file + ".tmp"
			if err := os.WriteFile(tmp, data, 0600); err != nil {
				if s.log != nil {
					s.log.Warn("traffic write error", zap.Error(err))
				}
				continue
			}
			if err := os.Rename(tmp, s.file); err != nil {
				if s.log != nil {
					s.log.Warn("traffic rename error", zap.Error(err))
				}
				os.Remove(tmp)
			}
		}
	}
}
