package cbornode

import (
	"bytes"
	"context"
	"fmt"

	block "github.com/ipfs/go-block-format"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
	recbor "github.com/polydawn/refmt/cbor"
	atlas "github.com/polydawn/refmt/obj/atlas"
	cbg "github.com/whyrusleeping/cbor-gen"
)

type IpldStore interface {
	Get(ctx context.Context, c cid.Cid, out interface{}) error
	Put(ctx context.Context, v interface{}) (cid.Cid, error)
}

type IpldBlockstore interface {
	Get(cid.Cid) (block.Block, error)
	Put(block.Block) error
}

type BasicIpldStore struct {
	Blocks IpldBlockstore
	Atlas  *atlas.Atlas
}

var _ IpldStore = &BasicIpldStore{}

func NewCborStore(bs IpldBlockstore) *BasicIpldStore {
	return &BasicIpldStore{Blocks: bs}
}

func (s *BasicIpldStore) Get(ctx context.Context, c cid.Cid, out interface{}) error {
	blk, err := s.Blocks.Get(c)
	if err != nil {
		return err
	}

	cu, ok := out.(cbg.CBORUnmarshaler)
	if ok {
		if err := cu.UnmarshalCBOR(bytes.NewReader(blk.RawData())); err != nil {
			return NewSerializationError(err)
		}
		return nil
	}

	if s.Atlas == nil {
		return DecodeInto(blk.RawData(), out)
	} else {
		return recbor.UnmarshalAtlased(recbor.DecodeOptions{}, blk.RawData(), out, *s.Atlas)
	}
}

type cidProvider interface {
	Cid() cid.Cid
}

func (s *BasicIpldStore) Put(ctx context.Context, v interface{}) (cid.Cid, error) {
	mhType := uint64(mh.BLAKE2B_MIN + 31)
	mhLen := -1
	codec := uint64(cid.DagCBOR)

	var expCid cid.Cid
	if c, ok := v.(cidProvider); ok {
		expCid := c.Cid()
		pref := expCid.Prefix()
		mhType = pref.MhType
		mhLen = pref.MhLength
		codec = pref.Codec
	}

	cm, ok := v.(cbg.CBORMarshaler)
	if ok {
		buf := new(bytes.Buffer)
		if err := cm.MarshalCBOR(buf); err != nil {
			return cid.Undef, err
		}

		pref := cid.Prefix{
			Codec:    codec,
			MhType:   mhType,
			MhLength: mhLen,
			Version:  1,
		}
		c, err := pref.Sum(buf.Bytes())
		if err != nil {
			return cid.Undef, err
		}

		blk, err := block.NewBlockWithCid(buf.Bytes(), c)
		if err != nil {
			return cid.Undef, err
		}

		if err := s.Blocks.Put(blk); err != nil {
			return cid.Undef, err
		}

		blkCid := blk.Cid()
		if expCid != cid.Undef && blkCid != expCid {
			return cid.Undef, fmt.Errorf("your object is not being serialized the way it expects to")
		}

		return blkCid, nil
	}

	nd, err := WrapObject(v, mhType, mhLen)
	if err != nil {
		return cid.Undef, err
	}

	if err := s.Blocks.Put(nd); err != nil {
		return cid.Undef, err
	}

	ndCid := nd.Cid()
	if expCid != cid.Undef && ndCid != expCid {
		return cid.Undef, fmt.Errorf("your object is not being serialized the way it expects to")
	}

	return ndCid, nil
}

func NewSerializationError(err error) error {
	return SerializationError{err}
}

type SerializationError struct {
	err error
}

func (se SerializationError) Error() string {
	return se.err.Error()
}

func (se SerializationError) Unwrap() error {
	return se.err
}

func (se SerializationError) Is(o error) bool {
	_, ok := o.(*SerializationError)
	return ok
}
