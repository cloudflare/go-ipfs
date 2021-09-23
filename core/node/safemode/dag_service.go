package safemode

import (
	"context"

	blocklist "github.com/cloudflare/go-ipfs-blocklist"
	blocks "github.com/ipfs/go-block-format"
	cid "github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"
	mdag "github.com/ipfs/go-merkledag"
)

type dagService struct {
	d  ipld.DAGService
	bl blocklist.Blocklist
}

var _ ipld.DAGService = &dagService{}

// WrapDAG returns an ipld.DAGService which is identical to `d`, except that it
// refuses to load content in the Blocklist `bl`.
func WrapDAG(d ipld.DAGService, bl blocklist.Blocklist) ipld.DAGService {
	return &dagService{d, bl}
}

func (d *dagService) Get(ctx context.Context, id cid.Cid) (ipld.Node, error) {
	bad, err := d.bl.Contains(ctx, id)
	if err != nil {
		return nil, err
	} else if bad {
		blk, _ := blocks.NewBlockWithCid([]byte(ErrForbidden.Error()+"\n"), id)
		return &mdag.RawNode{Block: blk}, ErrForbidden
	}
	return d.d.Get(ctx, id)
}

func (d *dagService) GetMany(ctx context.Context, ids []cid.Cid) <-chan *ipld.NodeOption {
	out := make(chan *ipld.NodeOption)

	go func() {
		defer close(out)

		for _, id := range ids {
			bad, err := d.bl.Contains(ctx, id)
			if err != nil {
				out <- &ipld.NodeOption{Err: err}
				return
			} else if bad {
				out <- &ipld.NodeOption{Err: ErrForbidden}
				return
			}
		}

		for opt := range d.d.GetMany(ctx, ids) {
			out <- opt
		}
	}()

	return out
}

func (d *dagService) Add(ctx context.Context, n ipld.Node) error {
	return d.d.Add(ctx, n)
}

func (d *dagService) Remove(ctx context.Context, id cid.Cid) error {
	return d.d.Remove(ctx, id)
}

func (d *dagService) AddMany(ctx context.Context, ns []ipld.Node) error {
	return d.d.AddMany(ctx, ns)
}

func (d *dagService) RemoveMany(ctx context.Context, ids []cid.Cid) error {
	return d.d.RemoveMany(ctx, ids)
}
