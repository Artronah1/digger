package dns

import (
	"context"
	"net"
	"sync"
	"time"
)

type Resolver struct {
	mu    sync.RWMutex
	cache map[string]string // IP -> hostname
	queue chan string
}

func NewResolver() *Resolver {
	r := &Resolver{
		cache: make(map[string]string),
		queue: make(chan string, 256),
	}
	go r.worker()
	return r
}

// Lookup возвращает hostname для IP из кэша.
// Если ещё не резолвился — ставит в очередь и возвращает "".
func (r *Resolver) Lookup(ip string) string {
	r.mu.RLock()
	name, ok := r.cache[ip]
	r.mu.RUnlock()
	if ok {
		return name
	}

	// неблокирующая постановка в очередь
	select {
		case r.queue <- ip:
		default:
			// очередь переполнена, пропускаем
	}
	return ""
}

func (r *Resolver) worker() {
	for ip := range r.queue {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		names, err := net.DefaultResolver.LookupAddr(ctx, ip)
		cancel()

		name := ""
		if err == nil && len(names) > 0 {
			name = trimDot(names[0])
		}

		r.mu.Lock()
		r.cache[ip] = name
		r.mu.Unlock()
	}
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
