package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fnproxy/config"
	"fnproxy/models"

	bolt "go.etcd.io/bbolt"
)

const (
	defaultLogRetentionDays  = 7
	defaultMaxAccessLogCount = 10000
)

var (
	networkSamplesBucket = []byte("network_samples")
	accessLogsBucket     = []byte("access_logs")
)

type monitorStore struct {
	db *bolt.DB
}

func newMonitorStore(path string) (*monitorStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}

	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(networkSamplesBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(accessLogsBucket); err != nil {
			return err
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &monitorStore{db: db}, nil
}

func (s *monitorStore) appendNetworkSample(sample models.NetworkSample) error {
	if s == nil || s.db == nil {
		return nil
	}
	payload, err := json.Marshal(sample)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(networkSamplesBucket)
		if bucket == nil {
			return fmt.Errorf("network samples bucket not found")
		}
		if err := bucket.Put(timeOnlyKey(sample.Timestamp), payload); err != nil {
			return err
		}
		return pruneBefore(bucket, timeOnlyKey(time.Now().Add(-networkRetention)))
	})
}

func (s *monitorStore) listNetworkSamplesSince(since time.Time) ([]models.NetworkSample, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}

	var samples []models.NetworkSample
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(networkSamplesBucket)
		if bucket == nil {
			return nil
		}

		cursor := bucket.Cursor()
		for key, value := cursor.Seek(timeOnlyKey(since)); key != nil; key, value = cursor.Next() {
			var sample models.NetworkSample
			if err := json.Unmarshal(value, &sample); err != nil {
				continue
			}
			samples = append(samples, sample)
		}
		return nil
	})
	return samples, err
}

func (s *monitorStore) appendAccessLog(entry models.AccessLogEntry) error {
	if s == nil || s.db == nil {
		return nil
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(accessLogsBucket)
		if bucket == nil {
			return fmt.Errorf("access logs bucket not found")
		}
		if err := bucket.Put(timeCompositeKey(entry.Timestamp, entry.ID), payload); err != nil {
			return err
		}
		retentionDays, maxEntries := currentMonitorLimits()
		if err := pruneBefore(bucket, timeOnlyKey(time.Now().Add(-time.Duration(retentionDays)*24*time.Hour))); err != nil {
			return err
		}
		return pruneToMaxEntries(bucket, maxEntries)
	})
}

func (s *monitorStore) listAccessLogs(limit int, match func(models.AccessLogEntry) bool) ([]models.AccessLogEntry, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = defaultLogLimit
	}

	results := make([]models.AccessLogEntry, 0, limit)
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(accessLogsBucket)
		if bucket == nil {
			return nil
		}

		cursor := bucket.Cursor()
		for key, value := cursor.Last(); key != nil && len(results) < limit; key, value = cursor.Prev() {
			var entry models.AccessLogEntry
			if err := json.Unmarshal(value, &entry); err != nil {
				continue
			}
			if match == nil || match(entry) {
				results = append(results, entry)
			}
		}
		return nil
	})
	return results, err
}

func pruneBefore(bucket *bolt.Bucket, cutoff []byte) error {
	cursor := bucket.Cursor()
	for key, _ := cursor.First(); key != nil && string(key) < string(cutoff); key, _ = cursor.Next() {
		if err := bucket.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func pruneToMaxEntries(bucket *bolt.Bucket, maxEntries int) error {
	if maxEntries <= 0 {
		return nil
	}

	count := bucket.Stats().KeyN
	if count <= maxEntries {
		return nil
	}

	toDelete := count - maxEntries
	cursor := bucket.Cursor()
	for key, _ := cursor.First(); key != nil && toDelete > 0; key, _ = cursor.Next() {
		if err := bucket.Delete(key); err != nil {
			return err
		}
		toDelete--
	}
	return nil
}

func currentMonitorLimits() (retentionDays int, maxEntries int) {
	global := config.GetManager().GetConfig().Global
	retentionDays = global.LogRetentionDays
	maxEntries = global.MaxAccessLogEntries
	if retentionDays <= 0 {
		retentionDays = defaultLogRetentionDays
	}
	if maxEntries <= 0 {
		maxEntries = defaultMaxAccessLogCount
	}
	return retentionDays, maxEntries
}

func timeOnlyKey(ts time.Time) []byte {
	return []byte(fmt.Sprintf("%020d", ts.UnixNano()))
}

func timeCompositeKey(ts time.Time, id string) []byte {
	return []byte(fmt.Sprintf("%020d:%s", ts.UnixNano(), id))
}
