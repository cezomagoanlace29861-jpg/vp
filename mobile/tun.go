//go:build linux

package mobile

import (
	"errors"
	"strconv"
	"sync"
	"syscall"

	"github.com/xjasonlyu/tun2socks/v2/engine"
	"golang.org/x/sys/unix"
)

// MTU of the VPN interface; the app's VpnService.Builder uses the same.
// Packets never leave the device at this size (the proxy re-sends the data
// over ordinary connections), and large ones let the user-space network
// stack move far more data per packet, which raises download speed.
const MTU = 9000

var (
	tunMu  sync.Mutex
	tunFD  = -1 // the VpnService's descriptor; the app owns and closes it
	tunRun bool
)

// StartTun starts carrying the VPN's packets to the local proxy. fd is the
// VpnService's tunnel; it stays the app's to close after StopTun.
func StartTun(fd int32) error {
	addr := vpn.target()
	if addr == "" {
		return errors.New("not connected")
	}
	tunMu.Lock()
	defer tunMu.Unlock()
	if tunRun {
		stopLocked()
	}
	// Every core the engine starts later (tests, a new group) would
	// otherwise inherit the tunnel, and Android keeps a VPN up while any
	// process holds it open: Disconnect would leave it on.
	syscall.CloseOnExec(int(fd))
	tunFD = int(fd)
	return startLocked(addr)
}

// StopTun stops tun2socks.
func StopTun() {
	tunMu.Lock()
	defer tunMu.Unlock()
	stopLocked()
	tunFD = -1
}

// retarget points a running tunnel at a new proxy address.
func retarget(addr string) {
	tunMu.Lock()
	defer tunMu.Unlock()
	if !tunRun {
		return
	}
	stopLocked()
	startLocked(addr)
}

func startLocked(addr string) error {
	if tunFD < 0 {
		return errors.New("no tunnel")
	}
	// tun2socks closes the descriptor it is given when it stops. The copy
	// is close-on-exec for the same reason as tunFD (see StartTun).
	dup, err := unix.FcntlInt(uintptr(tunFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	engine.Insert(&engine.Key{
		Device: "fd://" + strconv.Itoa(dup),
		Proxy:  "socks5://" + addr,
		MTU:    MTU,
		// Its warnings name the sites being visited.
		LogLevel: "silent",
	})
	// Every value above is valid, so engine.Start (which exits the process
	// on a bad key) cannot fail here.
	engine.Start()
	tunRun = true
	return nil
}

func stopLocked() {
	if tunRun {
		engine.Stop()
		tunRun = false
	}
}
