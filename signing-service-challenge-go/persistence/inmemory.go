package persistence

import (
	"errors"
	"sync"

	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/domain"
)

var (
	ErrDeviceNotFound = errors.New("device not found")
	ErrDeviceExists   = errors.New("device already exists")
)

type DeviceStore interface {
	Create(device domain.SignatureDevice) error
	Get(id string) (domain.SignatureDevice, error)
	Update(device domain.SignatureDevice) error
}

type InMemoryDeviceStore struct {
	devices map[string]domain.SignatureDevice
	mutex   sync.Mutex // map is not concurrency safe
}

func NewInMemoryDeviceStore() *InMemoryDeviceStore {
	return &InMemoryDeviceStore{
		devices: make(map[string]domain.SignatureDevice),
	}
}

func (s *InMemoryDeviceStore) Create(device domain.SignatureDevice) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.devices[device.ID]; exists {
		return ErrDeviceExists
	}

	s.devices[device.ID] = device
	return nil
}

func (s *InMemoryDeviceStore) Update(device domain.SignatureDevice) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	device, exists := s.devices[device.ID]
	if !exists {
		return ErrDeviceNotFound
	}
	s.devices[device.ID] = device

	return nil
}

func (s *InMemoryDeviceStore) Get(id string) (domain.SignatureDevice, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	device, exists := s.devices[id]
	if !exists {
		return domain.SignatureDevice{}, ErrDeviceNotFound
	}

	return device, nil
}
