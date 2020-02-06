// +build linux

package sockets

import (
	"fmt"
	"net"
	"os"
	"syscall"

	activation "github.com/coreos/go-systemd/v22/activation"
	manet "github.com/multiformats/go-multiaddr-net"
)

func isListening(file *os.File) (bool, error) {
	ret, err := syscall.GetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
	return ret == 1, err
}

func registerFile(file *os.File) error {
	listening, err := isListening(file)
	if err != nil {
		return fmt.Errorf("failed determine the socket type: %s", err)
	}

	if listening {
		listener, err := net.FileListener(file)
		if err != nil {
			return fmt.Errorf("failed to convert listener: %s", err)
		}
		mal, err := manet.WrapNetListener(listener)
		if err != nil {
			return fmt.Errorf("failed to wrap net listener: %s", err)
		}
		listeners[file.Name()] = append(listeners[file.Name()], mal)
	} else {
		pc, err := net.FilePacketConn(file)
		if err != nil {
			return fmt.Errorf("failed to convert to a packet conn: %s", err)
		}
		mapc, err := manet.WrapPacketConn(pc)
		if err != nil {
			return fmt.Errorf("failed to wrap net packet conn: %s", err)
		}
		packetConns[file.Name()] = append(packetConns[file.Name()], mapc)
	}
	return nil
}

func init() {
	// Initialize lazily as this isn't _free_.
	initFn = func() {
		for _, file := range activation.Files(true) {
			err := registerFile(file)
			file.Close()
			if err != nil {
				log.Errorf("when handling the socket %s: %s", file.Name(), err)
			}
		}
	}

}
