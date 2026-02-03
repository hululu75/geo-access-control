package geo_access_control

import (
	"container/list"
	"sync"
	"time"
)

// LRUCache is a thread-safe LRU cache with optional TTL expiration
type LRUCache struct {
	capacity int
	ttl      time.Duration
	cache    map[string]*list.Element
	lruList  *list.List
	mu       sync.RWMutex
}

type cacheEntry struct {
	key       string
	value     interface{}
	createdAt time.Time
}

// NewLRUCache creates a new LRU cache with the given capacity and TTL.
// A TTL of 0 means entries never expire (only evicted by capacity).
func NewLRUCache(capacity int, ttl time.Duration) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		ttl:      ttl,
		cache:    make(map[string]*list.Element),
		lruList:  list.New(),
	}
}

// Get retrieves a value from the cache.
// Returns (nil, false) if the key is not found or the entry has expired.
func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, found := c.cache[key]; found {
		entry := elem.Value.(*cacheEntry)

		// Check TTL expiration
		if c.ttl > 0 && time.Since(entry.createdAt) > c.ttl {
			// Entry expired, remove it
			c.lruList.Remove(elem)
			delete(c.cache, key)
			return nil, false
		}

		// Move to front (most recently used)
		c.lruList.MoveToFront(elem)
		return entry.value, true
	}

	return nil, false
}

// Set adds or updates a value in the cache
func (c *LRUCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if key already exists
	if elem, found := c.cache[key]; found {
		// Update value, reset timestamp, and move to front
		c.lruList.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		entry.value = value
		entry.createdAt = time.Now()
		return
	}

	// Add new entry
	entry := &cacheEntry{key: key, value: value, createdAt: time.Now()}
	elem := c.lruList.PushFront(entry)
	c.cache[key] = elem

	// Evict oldest if over capacity
	if c.lruList.Len() > c.capacity {
		c.evictOldest()
	}
}

// evictOldest removes the least recently used item
func (c *LRUCache) evictOldest() {
	elem := c.lruList.Back()
	if elem != nil {
		c.lruList.Remove(elem)
		entry := elem.Value.(*cacheEntry)
		delete(c.cache, entry.key)
	}
}

// Clear removes all items from the cache
func (c *LRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*list.Element)
	c.lruList.Init()
}

// Len returns the current number of items in the cache
func (c *LRUCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.lruList.Len()
}
