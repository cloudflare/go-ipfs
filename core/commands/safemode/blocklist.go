package safemode

import (
	"fmt"
	"io"
	"text/tabwriter"

	blocklist "github.com/cloudflare/go-ipfs-blocklist"
	"github.com/ipfs/go-cid"
	cmdenv "github.com/ipfs/go-ipfs/core/commands/cmdenv"
	iface "github.com/ipfs/interface-go-ipfs-core"

	cmds "github.com/ipfs/go-ipfs-cmds"
)

type SearchOutput struct {
	Output []*blocklist.BlocklistItem
}

const (
	reasonOptionName = "reason"
	userOptionName   = "user"
)

var blockCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Add content to a blocklist.",
		ShortDescription: `
Prevents CID associated to a given content to be served by the IPFS node.
This performs a content resolution, then prevents the resolved CID to be served
by the node, when operating with safemode enabled — 'ipfs daemon --safemode'.
Blocking action is logged. Every blocking action has to be given a reason using
'--reason' flag. A user can also be specified using '--user' flag. To access
the log, refer to 'ipfs safemode audit'.

Content can be any IPFS file or directory path, usually /ipfs/<CID>.
`,
		LongDescription: `
Prevents CID associated to a given content to be served by the IPFS node.
This performs a content resolution, then prevents the resolved CID to be served
by the node, when operating with safemode enabled — 'ipfs daemon --safemode'.
Blocking action is logged. Every blocking action has to be given a reason using
'--reason' flag. A user can also be specified using '--user' flag. To access
the log, refer to 'ipfs safemode audit'.

Content can be any IPFS file or directory. This includes
	- IPFS address, i.e. /ipfs/<CID>
	- IPNS address, i.e. /ipns/<hash_publickey>
	- DNSLink address, i.e. /ipns/example.com
	- HTTP URL, i.e. https://example.com/ or https://gateway.example.com/ipfs/<CID>

Examples:
	> ipfs safemode block -m 'good reason' /ipfs/<CID>
	<CID>

	> ipfs safemode block -m 'very good reason' https://example.com https://example.com/foo/bar
	<example.com_CID>
	<example.com/foo/bar_CID>
`,
	},

	Arguments: []cmds.Argument{
		cmds.StringArg("content", true, true, "Content to block."),
	},
	Options: []cmds.Option{
		cmds.StringOption(reasonOptionName, "m", "Reasons to block."),
		cmds.StringOption(userOptionName, "u", "User performing the block action."),
	},
	Run: func(req *cmds.Request, res cmds.ResponseEmitter, env cmds.Environment) error {
		api, err := cmdenv.GetApi(env, req)
		if err != nil {
			return err
		}

		reason, rok := req.Options[reasonOptionName].(string)
		user, _ := req.Options[userOptionName].(string)

		if !rok {
			return fmt.Errorf("A reason is needed to block content. It can be done as follow 'ipfs safemode block --reason=\"<reason>\"'")
		}

		data := blocklist.BlockData{
			Content: req.Arguments,
			Reason:  reason,
			User:    user,
		}
		rc, err := api.Safemode().Block(req.Context, data)

		if rc != nil {
			res.Emit(rc)
		}
		return err
	},
	Encoders: cmds.EncoderMap{
		cmds.Text: cmds.MakeTypedEncoder(func(req *cmds.Request, w io.Writer, rc *[]iface.ResolvedContent) error {
			for _, c := range *rc {
				_, err := fmt.Fprintln(w, c.Cid)
				if err != nil {
					return err
				}
			}
			return nil
		}),
	},
	Type: []iface.ResolvedContent{},
}

var unblockCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Remove content from a blocklist.",
		ShortDescription: `
Allow a CID associated to a given content to be served by the IPFS node. If
this CID was previously blocked, this is no longer the case.
This performs a content resolution, then removes the resolved CID to from the
node blocklist.
Unblocking action is logged. Every unblocking action has to be given a reason
using '--reason' flag. A user can also be specified using '--user' flag. To
access the log, refer to 'ipfs safemode audit'.

Content can be any IPFS file or directory path, usually /ipfs/<CID>.
`,
		LongDescription: `
Prevents CID associated to a given content to be served by the IPFS node.
This performs a content resolution, then prevents the resolved CID to be served
by the node, when operating with safemode enabled — 'ipfs daemon --safemode'.
Blocking action is logged. Every blocking action has to be given a reason using
'--reason' flag. A user can also be specified using '--user' flag. To access
the log, refer to 'ipfs safemode audit'.

Content can be any IPFS file or directory. This includes
	- IPFS address, i.e. /ipfs/<CID>
	- IPNS address, i.e. /ipns/<hash_publickey>
	- DNSLink address, i.e. /ipns/example.com
	- HTTP URL, i.e. https://example.com/ or https://gateway.example.com/ipfs/<CID>

Examples:
	> ipfs safemode unblock -m 'good reason' /ipfs/<CID>
	<CID>

	> ipfs safemode unblock -m 'very good reason' https://example.com https://example.com/foo/bar
	<example.com_CID>
	<example.com/foo/bar_CID>
`,
	},

	Arguments: []cmds.Argument{
		cmds.StringArg("content", true, true, "Content to unblock."),
	},
	Options: []cmds.Option{
		cmds.StringOption(reasonOptionName, "m", "Reasons to unblock."),
		cmds.StringOption(userOptionName, "u", "User performing the unblock action."),
	},
	Run: func(req *cmds.Request, res cmds.ResponseEmitter, env cmds.Environment) error {
		api, err := cmdenv.GetApi(env, req)
		if err != nil {
			return err
		}

		reason, rok := req.Options[reasonOptionName].(string)
		user, _ := req.Options[userOptionName].(string)

		if !rok {
			return fmt.Errorf("A reason is needed to unblock content. It can be done as follow 'ipfs safemode unblock --reason=\"<reason>\"'")
		}

		data := blocklist.BlockData{
			Content: req.Arguments,
			Reason:  reason,
			User:    user,
		}
		ids, err := api.Safemode().Unblock(req.Context, data)

		if ids != nil {
			res.Emit(ids)
		}
		return err
	},
	Encoders: cmds.EncoderMap{
		cmds.Text: cmds.MakeTypedEncoder(func(req *cmds.Request, w io.Writer, ids *[]cid.Cid) error {
			for _, id := range *ids {
				_, err := fmt.Fprintln(w, id)
				if err != nil {
					return err
				}
			}
			return nil
		}),
	},
	Type: []cid.Cid{},
}

var purgeCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Perform purge on IPFS node against given content.",
		ShortDescription: `
Purge the CID associated to a given content from the IPFS node. It removes the
content from the datastore and associated cache. This action is performed
automatically when a block action is performed.
Purge performs a content resolution, then removes the purge the resolved CID.

Content can be any IPFS file or directory path, usually /ipfs/<CID>.
`,
		LongDescription: `
Purge the CID associated to a given content from the IPFS node. It removes the
content from the datastore and associated cache. This action is performed
automatically when a block action is performed.
Purge performs a content resolution, then removes the purge the resolved CID.

Content can be any IPFS file or directory. This includes
	- IPFS address, i.e. /ipfs/<CID>
	- IPNS address, i.e. /ipns/<hash_publickey>
	- DNSLink address, i.e. /ipns/example.com
	- HTTP URL, i.e. https://example.com/ or https://gateway.example.com/ipfs/<CID>

Examples:
	> ipfs safemode purge /ipfs/<CID>
	<CID>

	> ipfs safemode purge https://example.com https://example.com/foo/bar
	<example.com_CID>
	<example.com/foo/bar_CID>
`,
	},

	Arguments: []cmds.Argument{
		cmds.StringArg("content", true, true, "Content to purge."),
	},
	Run: func(req *cmds.Request, res cmds.ResponseEmitter, env cmds.Environment) error {
		api, err := cmdenv.GetApi(env, req)
		if err != nil {
			return err
		}

		for _, c := range req.Arguments {
			id, err := api.Safemode().Purge(req.Context, c)
			if err != nil {
				return err
			}
			res.Emit(&id)
		}

		return nil
	},
	Encoders: cmds.EncoderMap{
		cmds.Text: cmds.MakeTypedEncoder(func(req *cmds.Request, w io.Writer, id *cid.Cid) error {
			_, err := fmt.Fprintln(w, id)
			return err
		}),
	},
	Type: cid.Cid{},
}

var searchCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "List entries in the blocklist associated to the given content.",
		ShortDescription: `
Displays the contents of an IPFS or IPNS object(s) associated to the given
content, with the following format:
		<hash> <blocking user> <blocked content> <block reason>

Content can be any IPFS file or directory path, usually /ipfs/<CID>.
`,
		LongDescription: `
Displays the contents of an IPFS or IPNS object(s) associated to the given
content, with the following format:
		<hash> <blocking user> <blocked content> <block reason>

Content can be any IPFS file or directory. This includes
	- IPFS address, i.e. /ipfs/<CID>
	- IPNS address, i.e. /ipns/<hash_publickey>
	- DNSLink address, i.e. /ipns/example.com
	- HTTP URL, i.e. https://example.com/ or https://gateway.example.com/ipfs/<CID>

Examples:
<CID1> is not blocked. /ipns/example.com was blocked and associated to <CID2>

	> ipfs safemode search /ipfs/<CID1> /ipfs/<CID2>
		<CID2> <user> [/ipns/example.com] <reason>

	> ipfs safemode search --headers /ipfs/<CID1> /ipfs/<CID2>
	  Hash   User   Content             Reason
		<CID2> <user> [/ipns/example.com] <reason>
`,
	},

	Arguments: []cmds.Argument{
		cmds.StringArg("content", true, true, "Content to search."),
	},
	Options: []cmds.Option{
		cmds.BoolOption(headersOptionNameTime, "v", "Print table headers (Hash, User, Content, Reason)."),
	},
	Run: func(req *cmds.Request, res cmds.ResponseEmitter, env cmds.Environment) error {
		api, err := cmdenv.GetApi(env, req)
		if err != nil {
			return err
		}

		items := make([]*blocklist.BlocklistItem, 0, len(req.Arguments))
		for _, c := range req.Arguments {
			bi, err := api.Safemode().Search(req.Context, c)
			if err != nil {
				return err
			}
			items = append(items, bi)
		}

		cmds.EmitOnce(res, SearchOutput{items})

		return nil
	},
	Encoders: cmds.EncoderMap{
		cmds.Text: cmds.MakeTypedEncoder(func(req *cmds.Request, w io.Writer, c *SearchOutput) error {
			return searchTabularOutput(req, w, c)
		}),
	},
	Type: SearchOutput{},
}

func searchTabularOutput(req *cmds.Request, w io.Writer, out *SearchOutput) error {
	headers, _ := req.Options[headersOptionNameTime].(bool)
	minTabWidth := 1

	tw := tabwriter.NewWriter(w, minTabWidth, 2, 1, ' ', 0)
	if headers {
		fmt.Fprintln(tw, "Hash\tUser\tContent\tReason")
	}

	for _, bi := range out.Output {
		if bi.User == "" {
			bi.User = "-"
		}

		fmt.Fprintf(tw, "%v\t%v\t%s\t%v\n", bi.Hash, bi.User, bi.Content, cmdenv.EscNonPrint(bi.Reason))
	}
	return tw.Flush()
}
