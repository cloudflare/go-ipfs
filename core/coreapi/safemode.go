package coreapi

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	blocklist "github.com/cloudflare/go-ipfs-blocklist"
	cid "github.com/ipfs/go-cid"
	safemode "github.com/ipfs/go-ipfs/core/node/safemode"
	ipld "github.com/ipfs/go-ipld-format"
	uio "github.com/ipfs/go-unixfs/io"
	coreiface "github.com/ipfs/interface-go-ipfs-core"
	ipath "github.com/ipfs/interface-go-ipfs-core/path"
)

var (
	errAlreadyBlocked    = fmt.Errorf("content was already blocked, but caches were purged again anyways")
	errNeedReasonToBlock = fmt.Errorf("A reason is needed to block content")
)

type invalidBlockErr struct {
	errs []error
}

func (err *invalidBlockErr) Error() string {
	if err == nil {
		return "<nil>"
	}

	sErrs := make([]string, 0)

	for _, e := range err.errs {
		sErrs = append(sErrs, e.Error())
	}

	return strings.Join(sErrs, "\n")
}

// SafemodeAPI brings Safemode behavior to CoreAPI
type SafemodeAPI CoreAPI

func (api *SafemodeAPI) Block(ctx context.Context, data blocklist.BlockData) ([]coreiface.ResolvedContent, error) {
	if data.Reason == "" {
		return nil, errNeedReasonToBlock
	}

	rc, err := api.blockWithoutAudit(ctx, data)
	if len(rc) > 0 {
		blocked := make([]cid.Cid, 0, len(rc))
		blockedPaths := make([]string, len(rc))
		for _, c := range rc {
			blocked = append(blocked, c.Cid)
			blockedPaths = append(blockedPaths, c.Links...)
		}
		data.Blocked = blockedPaths
		subErr := api.AddLog(ctx, &blocklist.Action{
			Typ:       "block",
			Ids:       blocked,
			Reason:    data.Reason,
			User:      data.User,
			CreatedAt: time.Now(),
		})
		if err == nil && subErr != nil {
			return rc, fmt.Errorf("Content was blocked, but the action was not added to the audit log: %w", subErr)
		}
	}

	// Interpret the error and return the index page.
	if ibe, ok := err.(*invalidBlockErr); ok {
		return rc, ibe
	} else if err == errAlreadyBlocked {
		return rc, nil
	} else if err != nil {
		return nil, fmt.Errorf("Failed to block content: %w", err)
	}
	return rc, nil
}

func (api *SafemodeAPI) blockWithoutAudit(ctx context.Context, data blocklist.BlockData) ([]coreiface.ResolvedContent, error) {
	toBlock := data.Content
	blocked := make([]coreiface.ResolvedContent, 0)
	errs := make([]error, 0)

	for _, path := range toBlock {
		sub := data
		sub.Content = []string{strings.TrimSpace(path)}

		id, err := api.individualBlock(ctx, sub)
		if err != nil {
			errs = append(errs, fmt.Errorf("%v: %v", sub.Content, err))
		} else {
			blocked = append(blocked, id...)
		}
	}

	if len(errs) > 0 {
		return blocked, &invalidBlockErr{errs}
	}

	return blocked, nil
}

func (api *SafemodeAPI) Unblock(ctx context.Context, data blocklist.BlockData) ([]cid.Cid, error) {
	if data.Reason == "" {
		return nil, errNeedReasonToBlock
	}

	unblocked := make([]cid.Cid, 0, len(data.Content))
	errs := make([]error, 0)
	for _, c := range data.Content {
		rc, err := api.ResolveContent(ctx, c)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		err = api.safeMode.Unblock(rc.Cid)
		if err != nil {
			errs = append(errs, fmt.Errorf("%v: %v", rc.Cid.String(), err))
			continue
		}
		unblocked = append(unblocked, rc.Cid)
	}

	act := blocklist.Action{
		Typ:       "unblock",
		Ids:       unblocked,
		Reason:    data.Reason,
		User:      data.User,
		CreatedAt: time.Now(),
	}

	var err error
	if len(errs) > 0 {
		err = &invalidBlockErr{errs}
	}
	if len(unblocked) > 0 {
		subErr := api.AddLog(ctx, &act)
		if err == nil && subErr != nil {
			return unblocked, fmt.Errorf("Content was unblocked, but the action was not added to the audit log: %w", subErr)
		}
	}

	return unblocked, err
}

func (api *SafemodeAPI) Search(ctx context.Context, content string) (*blocklist.BlocklistItem, error) {
	rc, err := api.ResolveContent(ctx, content)
	if err != nil {
		return nil, err
	}
	return api.safeMode.Search(rc.Cid)
}

func (api *SafemodeAPI) Purge(ctx context.Context, content string) (cid.Cid, error) {
	rc, err := api.ResolveContent(ctx, content)
	if err != nil {
		return cid.Cid{}, err
	}
	return rc.Cid, api.safeMode.Purge(rc.Cid)
}

func (api *SafemodeAPI) GetLogs(ctx context.Context, limit int) ([]*blocklist.Action, error) {
	return api.safeMode.GetLogs(limit)
}

func (api *SafemodeAPI) AddLog(ctx context.Context, act *blocklist.Action) error {
	return api.safeMode.AddLog(act)
}

func (api *SafemodeAPI) Contains(ctx context.Context, id cid.Cid) (bool, error) {
	return api.safeMode.Contains(ctx, id)
}

func (api *SafemodeAPI) ResolveContent(ctx context.Context, content string) (*coreiface.ResolvedContent, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	urlPath, err := api.contentName(content)
	if err != nil {
		return nil, fmt.Errorf("invalid ipfs path: %w", err)
	}
	urlPath, err = url.PathUnescape(urlPath)
	if err != nil {
		return nil, fmt.Errorf("invalid ipfs path: %w", err)
	}
	parsedPath := ipath.New(urlPath)
	if err := parsedPath.IsValid(); err != nil {
		return nil, fmt.Errorf("invalid ipfs path: %w", err)
	}
	// Resolve path to the final DAG node.
	resolvedPath, err := (*CoreAPI)(api).ResolvePath(ctx, parsedPath)
	if err != nil {
		return nil, fmt.Errorf("ipfs resolve: %w", err)
	}

	// Check if path leads to a file, and return if so.
	dr, err := (*CoreAPI)(api).Unixfs().Get(ctx, resolvedPath)
	if err == nil {
		dr.Close()
		return &coreiface.ResolvedContent{Cid: resolvedPath.Cid()}, nil
	}
	if err == safemode.ErrForbidden {
		return &coreiface.ResolvedContent{Cid: resolvedPath.Cid()}, nil
	}
	if err != uio.ErrIsDir {
		return nil, fmt.Errorf("ipfs cat: %w", err)
	}

	// This is a directory; check if it has an index or not and return.
	nd, err := (*CoreAPI)(api).ResolveNode(ctx, resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("internal error: %w", err)
	}
	dirr, err := uio.NewDirectoryFromNode(api.nd.DAG, nd)
	if err != nil {
		return nil, fmt.Errorf("internal error: %w", err)
	}
	links := make([]string, 0)
	dirr.ForEachLink(ctx, func(link *ipld.Link) error {
		links = append(links, link.Name)
		return nil
	})

	return &coreiface.ResolvedContent{Cid: resolvedPath.Cid(), Links: links}, nil
}

func (api *SafemodeAPI) individualBlock(ctx context.Context, data blocklist.BlockData) ([]coreiface.ResolvedContent, error) {
	data.Content = []string{sanitizeURL(data.Content[0])}

	resolved, err := api.ResolveContent(ctx, data.Content[0])
	if err != nil {
		return nil, err
	}

	if resolved.Links != nil { // The referenced content is a directory, not a file.
		// To future devs: do NOT implement a recursive blocking strategy
		// It blocks resources that can be shared accross websites, as a resource is described by its CID
		// Reference RTG-565
		// Block solely index.html.
		sub := data
		sub.Content = []string{"/ipfs/" + resolved.Cid.String() + "/index.html"}
		rc, err := api.blockWithoutAudit(ctx, sub)
		return rc, err
	}

	nexists, err := api.safeMode.Block(resolved.Cid, data) // Prevent content from being accessed again.
	if err != nil {
		return nil, err
	}
	err = api.safeMode.Purge(resolved.Cid) // Purge content from Postgres.
	if err != nil {
		return nil, fmt.Errorf("error encountered while purging long-term cache: %v", err)
	}

	if !nexists {
		return nil, errAlreadyBlocked
	}
	return []coreiface.ResolvedContent{*resolved}, nil
}

// contentName takes a user-provided URL or path served from IPFS, and returns
// the name that should be resolved.
func (api *SafemodeAPI) contentName(in string) (string, error) {
	in = strings.TrimPrefix(in, "http://")
	in = strings.TrimPrefix(in, "https://")
	in = path.Clean(in)
	if fragment := strings.Index(in, "#"); fragment != -1 {
		in = in[:fragment]
	}

	// If this is already a proper IPFS url, return it.
	if strings.HasPrefix(in, "/") {
		if strings.HasPrefix(in, "/ipfs/") || strings.HasPrefix(in, "/ipns/") {
			return in, nil
		}
		return "", fmt.Errorf("direct path given, but path doesn't start with /ipfs/ or /ipns/")
	}

	// Extract host and hostname.
	host := strings.SplitN(in, "/", 2)[0]
	hostname := strings.SplitN(host, ":", 2)[0]

	// If this is a direct link to a gateway, return the path.
	p := strings.TrimPrefix(in, host)
	if strings.HasPrefix(p, "/ipfs/") || strings.HasPrefix(p, "/ipns/") {
		return p, nil
	}

	// Handle direct links to subdomain gateway.
	nameFragment := strings.Split(hostname, ".")
	nFragments := len(nameFragment)
	if nFragments >= 4 && (nameFragment[nFragments-3] == "ipfs" || nameFragment[nFragments-3] == "ipns") {
		hash := strings.Join(nameFragment[:nFragments-3], ".")
		return "/" + nameFragment[nFragments-3] + "/" + hash + p, nil
	}

	// This must be a URL with a domain that has CNAME'd to a gateway, or an invalid URL.
	// We could filter if we knew the Hostnames the gateway is served on.
	return path.Join("/ipns/", in), nil
}

func sanitizeURL(url string) string {
	// remove URL query string
	withoutQuery := strings.Split(url, "?")[0]
	// Remove URL hash string
	withoutHash := strings.Split(withoutQuery, "#")[0]
	return withoutHash
}
