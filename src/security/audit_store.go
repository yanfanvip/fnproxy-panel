package security

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fnproxy/models"

	bolt "go.etcd.io/bbolt"
)

const (
	defaultSecurityLogRetentionDays = 30
	defaultMaxSecurityLogCount      = 5000
)

var securityLogsBucket = []byte("security_logs")

type auditStore struct {
	db *bolt.DB
}

func newAuditStore(path string) (*auditStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}

	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(securityLogsBucket)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &auditStore{db: db}, nil
}

func (s *auditStore) appendLog(entry models.SecurityLogEntry, maxEntries int) error {
	if s == nil || s.db == nil {
		return nil
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(securityLogsBucket)
		if bucket == nil {
			return fmt.Errorf("security logs bucket not found")
		}
		if err := bucket.Put(timeCompositeKey(entry.Timestamp, entry.ID), payload); err != nil {
			return err
		}
		// 清理超限日志
		return pruneToMaxEntries(bucket, maxEntries)
	})
}

func (s *auditStore) queryLogs(logType, level, keyword string, page, pageSize int) ([]models.SecurityLogEntry, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, nil
	}

	var allLogs []models.SecurityLogEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(securityLogsBucket)
		if bucket == nil {
			return nil
		}

		cursor := bucket.Cursor()
		// 从最新开始遍历
		for key, value := cursor.Last(); key != nil; key, value = cursor.Prev() {
			var entry models.SecurityLogEntry
			if err := json.Unmarshal(value, &entry); err != nil {
				continue
			}
			// 类型过滤
			if logType != "" && string(entry.Type) != logType {
				continue
			}
			// 级别过滤
			if level != "" && string(entry.Level) != level {
				continue
			}
			// 关键词搜索
			if keyword != "" {
				if !containsKeyword(entry, keyword) {
					continue
				}
			}
			allLogs = append(allLogs, entry)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	total := len(allLogs)

	// 分页
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 50
	}
	start := (page - 1) * pageSize
	if start >= total {
		return []models.SecurityLogEntry{}, total, nil
	}
	end := start + pageSize
	if end > total {
		end = total
	}

	return allLogs[start:end], total, nil
}

func (s *auditStore) getStats() (map[string]int, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}

	stats := map[string]int{
		"total":          0,
		"oauth_login":    0,
		"proxy_error":    0,
		"ssh_connect":    0,
		"system_operate": 0,
	}

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(securityLogsBucket)
		if bucket == nil {
			return nil
		}

		cursor := bucket.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			var entry models.SecurityLogEntry
			if err := json.Unmarshal(value, &entry); err != nil {
				continue
			}
			stats["total"]++
			stats[string(entry.Type)]++
		}
		return nil
	})
	return stats, err
}

func (s *auditStore) clearLogs() error {
	if s == nil || s.db == nil {
		return nil
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket(securityLogsBucket); err != nil && err != bolt.ErrBucketNotFound {
			return err
		}
		_, err := tx.CreateBucket(securityLogsBucket)
		return err
	})
}

func containsKeyword(entry models.SecurityLogEntry, keyword string) bool {
	return containsStr(entry.Username, keyword) ||
		containsStr(entry.RemoteAddr, keyword) ||
		containsStr(entry.Target, keyword) ||
		containsStr(entry.Action, keyword) ||
		containsStr(entry.Message, keyword)
}

func containsStr(s, substr string) bool {
	if len(s) == 0 || len(substr) == 0 {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func timeCompositeKey(ts time.Time, id string) []byte {
	return []byte(fmt.Sprintf("%020d:%s", ts.UnixNano(), id))
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
