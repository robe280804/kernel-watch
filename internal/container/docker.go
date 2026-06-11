package container

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// dockerSocket is the read-only Docker Engine API socket mounted into the
// container (see docker-compose.yml). All enrichment is best-effort: if the
// socket is unreachable we silently fall back to the short container ID.
const dockerSocket = "/var/run/docker.sock"

// dockerEnricher resolves container ID → name/image via the Docker Engine API,
// caching the full container list and refreshing it on a TTL. One list call
// enriches every container, which is far cheaper than per-PID inspects.
type dockerEnricher struct {
	client *http.Client

	mu       sync.RWMutex
	cache    map[string]ContainerMeta // keyed by full AND short (12-char) ID
	lastSync time.Time
	ttl      time.Duration
}

func newDockerEnricher() *dockerEnricher {
	return &dockerEnricher{
		client: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				// Dial the Unix socket regardless of the dummy URL host.
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", dockerSocket)
				},
			},
		},
		cache: make(map[string]ContainerMeta),
		ttl:   30 * time.Second,
	}
}

// lookup returns metadata for a container ID (full or short), refreshing the
// cached container list first if it is older than the TTL. The bool is false
// when Docker is unreachable or the container is unknown.
func (d *dockerEnricher) lookup(id string) (ContainerMeta, bool) {
	d.mu.RLock()
	meta, ok := d.cache[id]
	fresh := time.Since(d.lastSync) < d.ttl
	d.mu.RUnlock()

	if ok && fresh {
		return meta, true
	}
	if !fresh {
		d.refresh()
		d.mu.RLock()
		meta, ok = d.cache[id]
		d.mu.RUnlock()
	}
	return meta, ok
}

// refresh pulls the current container list from the Docker socket. On failure
// it still stamps lastSync so a missing socket doesn't trigger a call per event.
func (d *dockerEnricher) refresh() {
	data, err := d.get("/containers/json")
	if err != nil {
		d.mu.Lock()
		d.lastSync = time.Now()
		d.mu.Unlock()
		return
	}
	m, err := ParseDockerList(data)
	if err != nil {
		d.mu.Lock()
		d.lastSync = time.Now()
		d.mu.Unlock()
		return
	}
	d.mu.Lock()
	d.cache = m
	d.lastSync = time.Now()
	d.mu.Unlock()
}

// get performs a GET against the Docker API over the Unix socket. The host part
// of the URL is a placeholder — the transport always dials the socket.
func (d *dockerEnricher) get(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("docker api %s: status %d", path, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
