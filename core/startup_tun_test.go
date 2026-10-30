package core

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// Signals the exact offset captured by the official constructor-started reader,
// without gating or changing it. Used to reproduce an unmodified legacy peer.
type firstReadSignalTun struct {
	tun.Device
	started chan int
	once    sync.Once
}

func (t *firstReadSignalTun) Read(b [][]byte, sizes []int, offset int) (int, error) {
	t.once.Do(func() { t.started <- offset })
	return t.Device.Read(b, sizes, offset)
}

type observedInnerTun struct {
	tun.Device
	offsets chan int
}

func (t *observedInnerTun) Read(b [][]byte, sizes []int, offset int) (int, error) {
	select {
	case t.offsets <- offset:
	default:
	}
	return t.Device.Read(b, sizes, offset)
}

type countingBind struct {
	conn.Bind
	opens atomic.Int32
}

func (b *countingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.opens.Add(1)
	return b.Bind.Open(port)
}

func TestStartupTunReloadsConfiguredPaddingBeforeFirstPacket(t *testing.T) {
	inner, _, e := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.202.0.2")}, nil, 1420)
	if e != nil {
		t.Fatal(e)
	}
	observed := &observedInnerTun{Device: inner, offsets: make(chan int, 2)}
	managed := newStartupTun(observed)
	entered := &firstReadSignalTun{Device: managed, started: make(chan int, 1)}
	bind := &countingBind{Bind: conn.NewStdNetBind()}
	d := device.NewDevice(entered, bind, device.NewLogger(device.LogLevelSilent, ""))
	defer d.Close()
	select {
	case offset := <-entered.started:
		if offset != device.MessageTransportHeaderSize {
			t.Fatalf("expected initial default offset, got %d", offset)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("official reader did not start")
	}
	if e = d.IpcSet("s4=10\n"); e != nil {
		t.Fatal("configuration rejected")
	}
	managed.configured()
	select {
	case offset := <-observed.offsets:
		if offset != device.MessageTransportHeaderSize+10 {
			t.Fatalf("first real read used stale padding offset %d", offset)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("configured reader did not resume")
	}
	if bind.opens.Load() != 0 {
		t.Fatal("configuration validation implicitly opened a UDP bind")
	}
}

func TestStartupTunCloseUnblocksFailedConfiguration(t *testing.T) {
	inner, _, e := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.202.0.2")}, nil, 1420)
	if e != nil {
		t.Fatal(e)
	}
	managed := newStartupTun(inner)
	entered := &firstReadSignalTun{Device: managed, started: make(chan int, 1)}
	d := device.NewDevice(entered, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	select {
	case <-entered.started:
	case <-time.After(3 * time.Second):
		d.Close()
		t.Fatal("reader did not start")
	}
	if d.IpcSet("s4=invalid\n") == nil {
		d.Close()
		t.Fatal("invalid configuration accepted")
	}
	done := make(chan struct{})
	go func() { d.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung behind the initial read gate")
	}
}
