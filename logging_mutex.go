// +build mutexlog

package bchutil

import (
	"os"
	"sync"

	"github.com/gcash/bchlog"
)

// Create a logger for all mutexes to use
var mutexLogger bchlog.Logger

func init() {
	mutexLogger = bchlog.NewBackend(os.Stdout).Logger("MUTEX")
	mutexLogger.SetLevel(bchlog.LevelInfo)
}

// Mutex wraps a sync.Mutex and adds logging around its actions
type Mutex struct {
	name string
	sync.Mutex
}

// NewMutex creates a new `Mutex` whose actions with be logged and labeled with
// the given name
func NewMutex(name string) Mutex {
	return Mutex{name, sync.Mutex{}}
}

// Lock intercepts calls to lock this mutex and wraps logging around it
func (m *Mutex) Lock() {
	mutexLogger.Info("Locking mutex:", m.name)
	m.Mutex.Lock()
	mutexLogger.Info("Locked mutex:", m.name)
}

// Unlock intercepts calls to unlock this mutex and wraps logging around it
func (m *Mutex) Unlock() {
	mutexLogger.Info("Unlocking mutex:", m.name)
	m.Mutex.Unlock()
	mutexLogger.Info("Unlocked mutex:", m.name)
}

// RWMutex wraps a sync.RWMutex and adds logging around its actions
type RWMutex struct {
	name string
	sync.RWMutex
}

// NewRWMutex creates a new `RWMutex` whose actions with be logged and labeled
// with the given name
func NewRWMutex(name string) RWMutex {
	return RWMutex{name, sync.RWMutex{}}
}

// Lock intercepts calls to lock this mutex and wraps logging around it
func (m *RWMutex) Lock() {
	mutexLogger.Info("Locking mutex:", m.name)
	m.RWMutex.Lock()
	mutexLogger.Info("Locked mutex:", m.name)
}

// Unlock intercepts calls to unlock this mutex and wraps logging around it
func (m *RWMutex) Unlock() {
	mutexLogger.Info("Unlocking mutex:", m.name)
	m.RWMutex.Unlock()
	mutexLogger.Info("Unlocked mutex:", m.name)
}

// RLock intercepts calls to rlock this mutex and wraps logging around it
func (m *RWMutex) RLock() {
	mutexLogger.Info("RLocking mutex:", m.name)
	m.RWMutex.RLock()
	mutexLogger.Info("RLocked mutex:", m.name)
}

// RUnlock intercepts calls to runlock this mutex and wraps logging around it
func (m *RWMutex) RUnlock() {
	mutexLogger.Info("RUnlocking mutex:", m.name)
	m.RWMutex.RUnlock()
	mutexLogger.Info("RUnlocked mutex:", m.name)
}
