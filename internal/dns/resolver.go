package dns

import (
	"context"
	"net"
	"sync"
	"time"
)

const (
	lookupTimeout = 2 * time.Second
	positiveTTL   = 10 * time.Minute // успешный результат
	negativeTTL   = 30 * time.Second // неудача — ретрай позже
	resolverSweep = time.Minute
)

type entry struct {
	name     string
	resolved time.Time
	failed   bool
}

func (e entry) expired(now time.Time) bool {
	ttl := positiveTTL
	if e.failed {
		ttl = negativeTTL
	}
	return now.Sub(e.resolved) >= ttl
}

// Resolver — асинхронный rDNS: Lookup никогда не блокируется,
// незнакомый IP ставится в очередь (один раз), результат заберётся
// следующим Lookup.
type Resolver struct {
	mu        sync.RWMutex
	cache     map[string]entry
	pending   map[string]bool // IP уже в очереди
	queue     chan string
	closed    chan struct{}
	closeOnce sync.Once
	lastSweep time.Time
}

func NewResolver() *Resolver {
	r := &Resolver{
		cache:   make(map[string]entry),
		pending: make(map[string]bool),
		queue:   make(chan string, 256),
		closed:  make(chan struct{}),
	}
	go r.worker()
	return r
}

// Close останавливает worker. Идемпотентен. Канал очереди НЕ закрывается
// (send на закрытый канал — паника): worker выходит по closed,
// буфер просто остаётся.
func (r *Resolver) Close() {
	r.closeOnce.Do(func() { close(r.closed) })
}

// Lookup возвращает hostname для IP или "".
func (r *Resolver) Lookup(ip string) string {
	now := time.Now()

	r.mu.RLock()
	e, ok := r.cache[ip]
	pending := r.pending[ip]
	r.mu.RUnlock()

	if ok && !e.expired(now) {
		return e.name // в т.ч. "" для свежей неудачи (negative cache)
	}
	if pending {
		return "" // уже в очереди
	}

	select {
	case r.queue <- ip:
		r.mu.Lock()
		r.pending[ip] = true
		r.mu.Unlock()
	default:
		// очередь переполнена — попробуем в следующем цикле
	}
	return ""
}

func (r *Resolver) worker() {
	for {
		select {
		case ip := <-r.queue:
			r.resolve(ip)
		case <-r.closed:
			return
		}
	}
}

func (r *Resolver) resolve(ip string) {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	cancel()

	e := entry{resolved: time.Now()}
	if err == nil && len(names) > 0 {
		e.name = trimDot(names[0])
	} else {
		e.failed = true // раньше неудача кэшировалась навсегда
	}

	r.mu.Lock()
	r.cache[ip] = e
	delete(r.pending, ip)

	// Кэш никогда не чистился — рос бесконечно.
	if now := time.Now(); now.Sub(r.lastSweep) >= resolverSweep {
		r.lastSweep = now
		for k, e := range r.cache {
			if e.expired(now) {
				delete(r.cache, k)
			}
		}
	}
	r.mu.Unlock()
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
