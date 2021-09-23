package safemode

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	blocklist "github.com/cloudflare/go-ipfs-blocklist"
	cmds "github.com/ipfs/go-ipfs-cmds"
	cmdenv "github.com/ipfs/go-ipfs/core/commands/cmdenv"
)

const (
	headersOptionNameTime = "headers"
	limitOptionName       = "limit"
)

type AuditOutput struct {
	Output []*blocklist.Action
}

var auditCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Get audit logs for actions performed against the safemode.",
		ShortDescription: `
Displays the actions performed against the safemode, with the following format:
	<time in RFC3339 format> <action type> <user> <cids> <reason>
`,
		LongDescription: `
Displays the actions performed against the safemode, with the following format:
		<time in RFC3339 format> <action type> <user> <cids> <reason>

Time is formatted according to RFC3339, i.e. '2006-01-02T15:04:05+07:00'.
Action type is either 'block' or 'unblock'.
User is marked as '-' if it was not specified at the time of creation.
There might be multiple CIDs if these were grouped in the same action.
Reason is a standard text field.

Example:
	> ipfs safemode audit --headers
	Created										Action	User		CIDs					Reason
	2016-01-02T15:04:05+07:00 unblock -				<CID1> <CID2> very good reason
	2006-01-02T15:04:05+07:00 block  	janedoe <CID1> 				good reason
`,
	},
	Options: []cmds.Option{
		cmds.IntOption(limitOptionName, "Number of records to request from the audit log.").WithDefault(100),
		cmds.BoolOption(headersOptionNameTime, "v", "Print table headers (Created, Action, User, CIDs, Reason)."),
	},
	Arguments: []cmds.Argument{},
	Run: func(req *cmds.Request, res cmds.ResponseEmitter, env cmds.Environment) error {
		api, err := cmdenv.GetApi(env, req)
		if err != nil {
			return err
		}

		limit, lok := req.Options[limitOptionName].(int)
		if !lok {
			return nil
		}

		acts, err := api.Safemode().GetLogs(req.Context, limit)
		if err != nil {
			return err
		}

		cmds.EmitOnce(res, AuditOutput{Output: acts})

		return nil
	},
	Encoders: cmds.EncoderMap{
		cmds.Text: cmds.MakeTypedEncoder(func(req *cmds.Request, w io.Writer, act *AuditOutput) error {
			return auditTabularOutput(req, w, act)
		}),
	},
	Type: AuditOutput{},
}

func auditTabularOutput(req *cmds.Request, w io.Writer, out *AuditOutput) error {
	headers, _ := req.Options[headersOptionNameTime].(bool)
	minTabWidth := 1

	tw := tabwriter.NewWriter(w, minTabWidth, 2, 1, ' ', 0)
	if headers {
		fmt.Fprintln(tw, "Created\tAction\tUser\tCIDs\tReason")
	}

	for _, act := range out.Output {
		if act.User == "" {
			act.User = "-"
		}

		idsString := strings.Trim(fmt.Sprint(act.Ids), "[]")
		fmt.Fprintf(tw, "%v\t%v\t%v\t%s\t%v\n", act.CreatedAt.Format(time.RFC3339), act.Typ, act.User, idsString, cmdenv.EscNonPrint(act.Reason))
	}
	return tw.Flush()
}
