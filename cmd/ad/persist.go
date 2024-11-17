package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type PersistDatabase struct {
	persistDir string
}

func (p *PersistDatabase) ValidateKey(key string) (string, error) {
	// Make sure the key is not empty.
	if key == "" {
		return "", fmt.Errorf("key cannot be empty")
	}

	// Make sure the key does not contain any path separators.
	if filepath.Base(key) != key {
		return "", fmt.Errorf("key cannot contain path separators")
	}

	return key, nil
}

func (p *PersistDatabase) getPath(group string, key string) string {
	return filepath.Join(p.persistDir, group, key)
}

func (p *PersistDatabase) ForEach(group string, cb func(key string, read func(value interface{}) error) error) error {
	dir := filepath.Join(p.persistDir, group)

	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}

	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}

		key := ent.Name()
		path := filepath.Join(dir, key)

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		if err := cb(key, func(value interface{}) error {
			return json.NewDecoder(f).Decode(value)
		}); err != nil {
			return err
		}
	}

	return nil
}

func (p *PersistDatabase) Set(group string, key string, value interface{}) error {
	validKey, err := p.ValidateKey(key)
	if err != nil {
		return err
	}

	path := p.getPath(group, validKey)

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write the value to the file.
	if err := json.NewEncoder(f).Encode(value); err != nil {
		return err
	}

	return nil
}

func (p *PersistDatabase) Get(group string, key string, value interface{}) error {
	validKey, err := p.ValidateKey(key)
	if err != nil {
		return err
	}

	path := p.getPath(group, validKey)

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Read the value from the file.
	if err := json.NewDecoder(f).Decode(value); err != nil {
		return err
	}

	return nil
}

func NewPersistDatabase(persistDir string) *PersistDatabase {
	return &PersistDatabase{
		persistDir: persistDir,
	}
}
