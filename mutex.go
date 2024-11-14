//go:build !mutexlog
// +build !mutexlog

package bchutil

import "sync"

// Mutex is used for non-logging mutexes and simply delegates all calls to the
// underlying sync.Mutex
type Mutex sync.Mutex

func NewMutex(_ string) Mutex { return Mutex{} }
func (m *Mutex) Lock()        { (*sync.Mutex)(m).Lock() }
func (m *Mutex) Unlock()      { (*sync.Mutex)(m).Unlock() }

// RWMutex is used for non-logging mutexes and simply delegates all calls to the
// underlying sync.RWMutex
type RWMutex sync.RWMutex

func NewRWMutex(_ string) RWMutex { return RWMutex{} }
func (m *RWMutex) Lock()          { (*sync.RWMutex)(m).Lock() }
func (m *RWMutex) Unlock()        { (*sync.RWMutex)(m).Unlock() }
func (m *RWMutex) RLock()         { (*sync.RWMutex)(m).RLock() }
func (m *RWMutex) RUnlock()       { (*sync.RWMutex)(m).RUnlock() }
func (m *RWMutex) RLocker()       { (*sync.RWMutex)(m).RLocker() }
