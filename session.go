// session.go
package main

import (
    "sync"
    "time"
    
    "github.com/go-webauthn/webauthn/webauthn"
)

type SessionData struct {
    Data        *webauthn.SessionData
    CreatedAt   time.Time
}

type SessionStore struct {
    sync.RWMutex
    store    map[uint64]*SessionData
    duration time.Duration
}

func NewSessionStore(expiration time.Duration) *SessionStore {
    ss := &SessionStore{
        store:    make(map[uint64]*SessionData),
        duration: expiration,
    }
    
    // Start cleanup goroutine
    go ss.cleanup()
    
    return ss
}

func (ss *SessionStore) cleanup() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        ss.Lock()
        for id, session := range ss.store {
            if time.Since(session.CreatedAt) > ss.duration {
                delete(ss.store, id)
            }
        }
        ss.Unlock()
    }
}

func (ss *SessionStore) Store(userID uint64, data *webauthn.SessionData) {
    ss.Lock()
    defer ss.Unlock()
    
    ss.store[userID] = &SessionData{
        Data:      data,
        CreatedAt: time.Now(),
    }
}

func (ss *SessionStore) Get(userID uint64) (*webauthn.SessionData, bool) {
    ss.RLock()
    defer ss.RUnlock()
    
    session, exists := ss.store[userID]
    if !exists {
        return nil, false
    }
    
    // Check if session has expired
    if time.Since(session.CreatedAt) > ss.duration {
        go func() {
            ss.Lock()
            delete(ss.store, userID)
            ss.Unlock()
        }()
        return nil, false
    }
    
    return session.Data, true
}

func (ss *SessionStore) Delete(userID uint64) {
    ss.Lock()
    defer ss.Unlock()
    delete(ss.store, userID)
}