package core

import (
	"os"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// startupTun coordinates the pinned engine's constructor-started TUN reader
// with initial IpcSet. RoutineReadFromTUN captures S4 before calling Read. Its
// first call may therefore hold the pre-configuration offset. Returning zero
// packets after configuration makes that loop reload S4 without consuming or
// dropping the first real IP packet. Configuration is immutable after startup.
type startupTun struct {
	tun.Device
	ready                          chan struct{}
	closed                         chan struct{}
	events                         chan tun.Event
	readyOnce, readOnce, closeOnce sync.Once
	closeErr                       error
}

func newStartupTun(inner tun.Device) *startupTun {
	return &startupTun{Device: inner, ready: make(chan struct{}), closed: make(chan struct{}), events: make(chan tun.Event)}
}
func (t *startupTun) configured() { t.readyOnce.Do(func() { close(t.ready) }) }
func (t *startupTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case <-t.ready:
	}
	first := false
	t.readOnce.Do(func() { first = true })
	if first {
		return 0, nil
	}
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	default:
	}
	return t.Device.Read(bufs, sizes, offset)
}

// CreateNetTUN queues EventUp immediately. Lifecycle is explicitly controlled
// here, so validation cannot implicitly open a UDP bind before Device.Up.
// This userspace TUN has an immutable MTU and no host link events to forward.
func (t *startupTun) Events() <-chan tun.Event { return t.events }
func (t *startupTun) Close() error {
	t.closeOnce.Do(func() { close(t.closed); t.closeErr = t.Device.Close(); close(t.events) })
	return t.closeErr
}
