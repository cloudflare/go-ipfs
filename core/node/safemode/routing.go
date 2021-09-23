package safemode

import (
	"context"
	"errors"
	"fmt"
	"time"

	blocklist "github.com/cloudflare/go-ipfs-blocklist"
	"github.com/ipfs/go-ipfs/core/node/libp2p"
	cache "github.com/ipfs/go-ipfs/core/node/safemode/cache"

	cid "github.com/ipfs/go-cid"
	ds "github.com/ipfs/go-datastore"
	p2phost "github.com/libp2p/go-libp2p-core/host"
	peer "github.com/libp2p/go-libp2p-core/peer"
	routing "github.com/libp2p/go-libp2p-core/routing"
	pstore "github.com/libp2p/go-libp2p-peerstore"
	record "github.com/libp2p/go-libp2p-record"
)

var routerCache = cache.New(30*time.Second, 10*time.Second, 65536)

// ErrForbidden is returned when the search is for blocked content.
var ErrForbidden = errors.New("routing: content is unavailable because it violates the gateway's terms of service")

type router struct {
	r  routing.Routing
	bl blocklist.Blocklist
}

var _ routing.Routing = &router{}

// WrapRouter returns a core.RoutingOption which is identical to `opt`, except
// that it will refuse to provide/search for content in the blocklist `bl`.
func WrapRouter(opt libp2p.RoutingOption, bl blocklist.Blocklist) libp2p.RoutingOption {
	return func(ctx context.Context, host p2phost.Host, dstore ds.Batching, validator record.Validator, peers ...peer.AddrInfo) (routing.Routing, error) {
		r, err := opt(ctx, host, dstore, validator, peers...)
		if err != nil {
			return nil, err
		}
		return &router{r, bl}, nil
	}
}

func (r *router) checkCID(ctx context.Context, id cid.Cid) bool {
	if blocked, ok := routerCache.Get(id.String()); ok {
		return blocked.(bool)
	}
	blocked, err := r.bl.Contains(ctx, id)
	if err != nil {
		return false
	}
	routerCache.Set(id.String(), blocked, cache.DefaultExpiration)

	if blocked {
		log.Warnf("tried to provide/find blocked content: %v\n", id.String())
	}

	return blocked
}

func (r *router) Provide(ctx context.Context, id cid.Cid, announce bool) error {
	if bad := r.checkCID(ctx, id); bad {
		return fmt.Errorf("will not try to provide blocked content")
	}
	return r.r.Provide(ctx, id, announce)
}

func (r *router) FindProvidersAsync(ctx context.Context, id cid.Cid, count int) <-chan pstore.PeerInfo {
	if bad := r.checkCID(ctx, id); bad {
		ch := make(chan pstore.PeerInfo)
		close(ch)
		return ch
	}
	return r.r.FindProvidersAsync(ctx, id, count)
}

func (r *router) FindPeer(ctx context.Context, id peer.ID) (pstore.PeerInfo, error) {
	return r.r.FindPeer(ctx, id)
}

func (r *router) PutValue(ctx context.Context, key string, val []byte, opts ...routing.Option) error {
	return r.r.PutValue(ctx, key, val, opts...)
}

func (r *router) GetValue(ctx context.Context, key string, opts ...routing.Option) ([]byte, error) {
	return r.r.GetValue(ctx, key, opts...)
}

func (r *router) SearchValue(ctx context.Context, key string, opts ...routing.Option) (<-chan []byte, error) {
	return r.r.SearchValue(ctx, key, opts...)
}

func (r *router) Bootstrap(ctx context.Context) error { return r.r.Bootstrap(ctx) }
