package container

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Info holds resolved information about a container.
type Info struct {
	ID        string // full 64-char Docker container ID
	ShortID   string // first 12 chars
	Name      string // human-readable name (e.g. "nginx")
	ImageName string // e.g. "nginx:alpine"
	ResolvedAt time.Time
}

// Mapper resolves PIDs to container metadata.
// It caches results to avoid hitting /proc on every event.
type Mapper struct {
	mu     sync.RWMutex
	cache  map[uint32]*Info // pid → container info (nil = host process)
	ttl    time.Duration
	docker *dockerEnricher // resolves container name/image via the Docker socket
}

// New creates a new Mapper with a cache TTL.
func New(cacheTTL time.Duration) *Mapper {
	m := &Mapper{
		cache:  make(map[uint32]*Info),
		ttl:    cacheTTL,
		docker: newDockerEnricher(),
	}
	// Evict stale entries periodically
	go m.evictLoop()
	return m
}

// Resolve returns container info for a given PID.
// Returns nil if the process is running on the host (not in a container).
func (m *Mapper) Resolve(pid uint32) (*Info, error) {
	// Check cache first
	m.mu.RLock()
	if info, ok := m.cache[pid]; ok {
		m.mu.RUnlock()
		return info, nil
	}
	m.mu.RUnlock()

	// Read from /proc
	info, err := m.resolveFromProc(pid)
	if err != nil {
		return nil, err
	}

	// Cache the result (even if nil = host process)
	m.mu.Lock()
	m.cache[pid] = info
	m.mu.Unlock()

	return info, nil
}

// resolveFromProc reads /proc/<pid>/cgroup and extracts the Docker container ID.
func (m *Mapper) resolveFromProc(pid uint32) (*Info, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		// Process may have exited — not an error we care about
		return nil, nil
	}

	containerID := extractContainerID(string(data))
	if containerID == "" {
		// Host process, not in a container
		return nil, nil
	}

	// Enrich with the container's real name/image via the Docker socket.
	// Falls back to the short ID when Docker is unreachable.
	info := &Info{
		ID:         containerID,
		ShortID:    containerID[:12],
		ResolvedAt: time.Now(),
	}

	if meta, ok := m.docker.lookup(containerID); ok && meta.Name != "" {
		info.Name = meta.Name
		info.ImageName = meta.Image
	} else {
		info.Name = containerID[:12]
	}

	return info, nil
}

// extractContainerID parses /proc/<pid>/cgroup content and returns the
// Docker container ID (64 hex chars) if found.
func extractContainerID(cgroupData string) string {
	for _, line := range strings.Split(cgroupData, "\n") {
		// Docker puts the container ID in the cgroup path
		// Format examples:
		//   12:memory:/docker/abc123...64chars
		//   0::/system.slice/docker-abc123...64chars.scope  (cgroups v2)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// cgroups v1: look for /docker/<64-char-id>
		if idx := strings.Index(line, "/docker/"); idx != -1 {
			rest := line[idx+len("/docker/"):]
			id := strings.SplitN(rest, "/", 2)[0]
			if len(id) == 64 && isHex(id) {
				return id
			}
		}

		// cgroups v2: look for docker-<64-char-id>.scope
		if idx := strings.Index(line, "docker-"); idx != -1 {
			rest := line[idx+len("docker-"):]
			id := strings.TrimSuffix(strings.SplitN(rest, ".", 2)[0], ".scope")
			if len(id) == 64 && isHex(id) {
				return id
			}
		}
	}
	return ""
}

// Invalidate removes a PID from the cache (call when a container stops).
func (m *Mapper) Invalidate(pid uint32) {
	m.mu.Lock()
	delete(m.cache, pid)
	m.mu.Unlock()
}

// evictLoop removes cache entries older than TTL.
func (m *Mapper) evictLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for pid, info := range m.cache {
			if info != nil && now.Sub(info.ResolvedAt) > m.ttl {
				delete(m.cache, pid)
			}
		}
		m.mu.Unlock()
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ── Docker container list (for enrichment) ───────────────────────────────────

// ContainerMeta holds metadata fetched from the Docker API.
type ContainerMeta struct {
	ID    string
	Name  string
	Image string
}

// dockerListResponse is a minimal struct for parsing Docker API responses.
type dockerListResponse struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
}

// ParseDockerList parses the output of `GET /containers/json` from the Docker API.
func ParseDockerList(data []byte) (map[string]ContainerMeta, error) {
	var list []dockerListResponse
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	result := make(map[string]ContainerMeta, len(list))
	for _, c := range list {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		meta := ContainerMeta{ID: c.ID, Name: name, Image: c.Image}
		// Index by full ID and short ID
		result[c.ID] = meta
		if len(c.ID) >= 12 {
			result[c.ID[:12]] = meta
		}
	}
	return result, nil
}
