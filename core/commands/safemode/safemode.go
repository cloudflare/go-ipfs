package safemode

import (
	cmds "github.com/ipfs/go-ipfs-cmds"
	logging "github.com/ipfs/go-log"
)

var log = logging.Logger("core/commands/safemode")

var SafemodeCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Interact with IPFS Safemode to prevent certain CIDs from being provided.",
		ShortDescription: `
Provides a familiar interface to prevent certain CIDs from being provided. CIDs
added to the blocklist are not reprovided, nor served by the IPFS node.
`,
	},

	Subcommands: map[string]*cmds.Command{
		"block":   blockCmd,
		"unblock": unblockCmd,
		"purge":   purgeCmd,
		"search":  searchCmd,
		"audit":   auditCmd,
	},
}
