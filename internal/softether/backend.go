package softether

import (
	"context"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/vpn"
)

// Backend plugs the native SoftEther client into the access-point registry.
type Backend struct{}

// NewBackend returns the SoftEther backend.
func NewBackend() vpn.Backend { return Backend{} }

func (Backend) Kind() string { return model.KindSoftEther }

func (Backend) Connect(ctx context.Context, point model.AccessPoint, creds vpn.Credentials) (vpn.Session, error) {
	return Connect(ctx, point, creds)
}
