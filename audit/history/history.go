package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sift/audit"
)

const maxScans = 30

type ScanRecord struct {
	Timestamp time.Time `json:"timestamp"`
	File      string    `json:"-"`
}

type Store struct {
	baseDir string
}

func NewStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}
	return &Store{baseDir: filepath.Join(home, ".sift", "history")}, nil
}

func (s *Store) Save(profile, command string, findings []audit.Finding) error {
	dir := filepath.Join(s.baseDir, profile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create history dir: %w", err)
	}

	ts := time.Now().UTC().Format("2006-01-02T15-04-05")
	filename := fmt.Sprintf("%s-%s.json", command, ts)
	path := filepath.Join(dir, filename)

	data, err := json.Marshal(findings)
	if err != nil {
		return fmt.Errorf("marsahl findings: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write history: %w", err)
	}

	s.prune(dir, command)
	return nil
}

func (s *Store) Latest(profile, command string) ([]audit.Finding, time.Time, error) {
	records, err := s.List(profile, command, 1)
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(records) == 0 {
		return nil, time.Time{}, nil
	}

	findings, err := s.load(records[0].File)
	if err != nil {
		return nil, time.Time{}, err
	}
	return findings, records[0].Timestamp, nil
}

func (s *Store) List(profile, command string, limit int) ([]ScanRecord, error) {
	dir := filepath.Join(s.baseDir, profile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read history dir: %w", err)
	}

	prefix := command + "-"
	var records []ScanRecord
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		ts, err := parseTimestamp(e.Name(), prefix)
		if err != nil {
			continue
		}
		records = append(records, ScanRecord{
			Timestamp: ts,
			File:      filepath.Join(dir, e.Name()),
		})
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.After(records[j].Timestamp)
	})

	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

func (s *Store) FindResource(profile, resourceID string) ([]audit.Finding, error) {
	dir := filepath.Join(s.baseDir, profile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var matches []audit.Finding
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		findings, err := s.load(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		for _, f := range findings {
			if f.ResourceID == resourceID {
				matches = append(matches, f)
			}
		}
	}
	return matches, nil
}

func (s *Store) load(path string) ([]audit.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var findings []audit.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, err
	}
	return findings, nil
}

func (s *Store) prune(dir, command string) {
	records, err := s.List(filepath.Base(dir), command, 0)
	if err != nil || len(records) <= maxScans {
		return
	}
	for _, r := range records[maxScans:] {
		os.Remove(r.File)
	}
}

func parseTimestamp(filename, prefix string) (time.Time, error) {
	name := strings.TrimPrefix(filename, prefix)
	name = strings.TrimSuffix(name, ".json")
	return time.Parse("2006-01-02T15-04-05", name)
}
