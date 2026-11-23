package vpn

import (
	"context"

	"github.com/qy/easyconnect/internal/model"
)

// Backend logs in to one kind of access point and returns its Session. The
// manager knows nothing about the protocol: aTrust, SoftEther and any future
// product plug in here.
type Backend interface {
	// Kind is the value stored in AccessPoint.Kind.
	Kind() string
	Connect(ctx context.Context, point model.AccessPoint, creds Credentials) (Session, error)
}

// backendFunc adapts a plain Connector to a Backend, for the kinds that are
// just a function.
type backendFunc struct {
	kind string
	conn Connector
}

// NewBackend wraps a Connector as a Backend of the given kind.
func NewBackend(kind string, conn Connector) Backend {
	return backendFunc{kind: kind, conn: conn}
}

func (b backendFunc) Kind() string { return b.kind }

func (b backendFunc) Connect(ctx context.Context, point model.AccessPoint, creds Credentials) (Session, error) {
	return b.conn(ctx, point, creds)
}
