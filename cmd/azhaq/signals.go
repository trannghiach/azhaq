package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// stopSignals end a command as Ctrl-C does: it stops sending, keeps what it
// found, seals the ledger, prints its summary and exits 4. SIGTERM is what
// kill, timeout, systemd and docker stop send; SIGHUP is a closed terminal.
var stopSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}

// stopContext is a context that ends on the first stop signal; a later one
// is held back too, so a shutdown that is under way (the ledger being
// sealed, the summary written) is not cut short. SIGKILL still ends it.
func stopContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), stopSignals...)
}
