package namesys

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/ipfs/go-ipfs/namesys/dnssec"
	dnscache "github.com/ipfs/go-ipfs/namesys/dnssec/cache"
	path "github.com/ipfs/go-path"
	opts "github.com/ipfs/interface-go-ipfs-core/options/namesys"
	isd "github.com/jbenet/go-is-domain"
)

const ethTLD = "eth"
const linkTLD = "link"

type LookupTXTFunc func(name string) (txt []string, err error)

// DNSResolver implements a Resolver on DNS domains
type DNSResolver struct {
	lookupTXT LookupTXTFunc
	// TODO: maybe some sort of caching?
	// cache would need a timeout
	dnssecResolver *dnssec.Resolver
}

// NewDNSResolver constructs a name resolver using DNS TXT records.
func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		lookupTXT: net.LookupTXT,
		dnssecResolver: &dnssec.Resolver{
			Cache: dnscache.New(10*time.Second, 5*time.Second, 4096),
		},
	}
}

// Resolve implements Resolver.
func (r *DNSResolver) Resolve(ctx context.Context, name string, options ...opts.ResolveOpt) (path.Path, error) {
	return resolve(ctx, r, name, opts.ProcessOpts(options))
}

// ResolveAsync implements Resolver.
func (r *DNSResolver) ResolveAsync(ctx context.Context, name string, options ...opts.ResolveOpt) <-chan Result {
	return resolveAsync(ctx, r, name, opts.ProcessOpts(options))
}

type lookupRes struct {
	path     path.Path
	cacheTag *string
	proof    [][]byte
	error    error
}

// resolveOnce implements resolver.
// TXT records for a given domain name should contain a b58
// encoded multihash.
func (r *DNSResolver) resolveOnceAsync(ctx context.Context, name string, needsProof bool, options opts.ResolveOpts) <-chan onceResult {
	var fqdn string
	out := make(chan onceResult, 1)
	segments := strings.SplitN(name, "/", 2)
	domain := segments[0]

	if !isd.IsDomain(domain) {
		out <- onceResult{err: errors.New("not a valid domain name")}
		close(out)
		return out
	}
	log.Debugf("DNSResolver resolving %s", domain)

	if strings.HasSuffix(domain, ".") {
		fqdn = domain
	} else {
		fqdn = domain + "."
	}

	if strings.HasSuffix(fqdn, "."+ethTLD+".") {
		// This is an ENS name.  As we're resolving via an arbitrary DNS server
		// that may not know about .eth we need to add our link domain suffix.
		fqdn += linkTLD + "."
	}

	rootChan := make(chan lookupRes, 1)
	go workDomain(ctx, r, fqdn, needsProof, rootChan)

	subChan := make(chan lookupRes, 1)
	go workDomain(ctx, r, "_dnslink."+fqdn, needsProof, subChan)

	appendPath := func(p path.Path) (path.Path, error) {
		if len(segments) > 1 {
			return path.FromSegments("", strings.TrimRight(p.String(), "/"), segments[1])
		}
		return p, nil
	}

	go func() {
		defer close(out)
		for {
			select {
			case subRes, ok := <-subChan:
				if !ok {
					subChan = nil
					break
				}
				if subRes.error == nil {
					p, err := appendPath(subRes.path)
					emitOnceResult(ctx, out, onceResult{value: p, cacheTag: subRes.cacheTag, proof: subRes.proof, err: err})
					return
				}
			case rootRes, ok := <-rootChan:
				if !ok {
					rootChan = nil
					break
				}
				if rootRes.error == nil {
					p, err := appendPath(rootRes.path)
					emitOnceResult(ctx, out, onceResult{value: p, cacheTag: rootRes.cacheTag, proof: rootRes.proof, err: err})
				}
			case <-ctx.Done():
				return
			}
			if subChan == nil && rootChan == nil {
				return
			}
		}
	}()

	return out
}

func workDomain(ctx context.Context, r *DNSResolver, name string, needsProof bool, res chan lookupRes) {
	defer close(res)

	var (
		txt   []string
		proof *dnssec.Result
		err   error
	)
	if needsProof {
		txt, proof, err = r.dnssecResolver.LookupTXT(ctx, name)
	} else {
		txt, err = r.lookupTXT(name)
	}
	if err != nil {
		res <- lookupRes{"", nil, nil, err}
		return
	}

	// Serialize proof, it one was computed
	var rawProof []byte
	if proof != nil {
		rawProof, err = proof.MarshalBinary()
		if err != nil {
			res <- lookupRes{"", nil, nil, err}
			return
		}
		rawProof = append([]byte{0}, rawProof...)
	}

	// Return first valid record
	for _, t := range txt {
		p, err := parseEntry(t)
		if err == nil {
			res <- lookupRes{p, dnsCacheTag(txt), [][]byte{rawProof}, nil}
			return
		}
	}
	res <- lookupRes{"", nil, nil, ErrResolveFailed}
}

func parseEntry(txt string) (path.Path, error) {
	p, err := path.ParseCidToPath(txt) // bare IPFS multihashes
	if err == nil {
		return p, nil
	}

	return tryParseDnsLink(txt)
}

func tryParseDnsLink(txt string) (path.Path, error) {
	parts := strings.SplitN(txt, "=", 2)
	if len(parts) == 2 && parts[0] == "dnslink" {
		return path.ParsePath(parts[1])
	}

	return "", errors.New("not a valid dnslink entry")
}

func dnsCacheTag(txt []string) *string {
	quoted := make([]string, 0)
	for _, t := range txt {
		quoted = append(quoted, fmt.Sprintf("%q", t))
	}
	sort.Strings(quoted)

	raw, err := json.Marshal(quoted)
	if err != nil {
		return nil
	}
	digest := fmt.Sprintf("%x", sha1.Sum(raw))

	return &digest
}
