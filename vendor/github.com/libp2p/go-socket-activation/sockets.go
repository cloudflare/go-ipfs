package sockets

import (
	"sync"

	logging "github.com/ipfs/go-log"
	manet "github.com/multiformats/go-multiaddr-net"
)

var (
	mu          sync.Mutex
	log         = logging.Logger("socket-activation")
	initFn      = func() {}
	initialized = false
	listeners   = make(map[string][]manet.Listener)
	packetConns = make(map[string][]manet.PacketConn)
)

func initialize() {
	if !initialized {
		initFn()
		initialized = true
	}
}

// TakeSockets takes the listeners associated with the given name.
func TakeListeners(name string) ([]manet.Listener, error) {
	mu.Lock()
	defer mu.Unlock()
	initialize()

	s := listeners[name]
	delete(listeners, name)

	return s, nil
}

// ListListeners lists the names of the available listeners.
func ListListeners() ([]string, error) {
	mu.Lock()
	defer mu.Unlock()
	initialize()

	names := make([]string, 0, len(listeners))
	for name := range listeners {
		names = append(names, name)
	}
	return names, nil
}

// TakePacketConns takes the packet connections associated with the given name.
func TakePacketConns(name string) ([]manet.PacketConn, error) {
	mu.Lock()
	defer mu.Unlock()
	initialize()

	s := packetConns[name]
	delete(packetConns, name)

	return s, nil
}

// ListListeners lists the names of the available packet connections.
func ListPacketConns() ([]string, error) {
	mu.Lock()
	defer mu.Unlock()
	initialize()

	names := make([]string, 0, len(packetConns))
	for name := range packetConns {
		names = append(names, name)
	}
	return names, nil
}
