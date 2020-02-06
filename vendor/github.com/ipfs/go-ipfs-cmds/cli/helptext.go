package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/template"

	cmds "github.com/ipfs/go-ipfs-cmds"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	defaultTerminalWidth = 80
	requiredArg          = "<%v>"
	optionalArg          = "[<%v>]"
	variadicArg          = "%v..."
	shortFlag            = "-%v"
	longFlag             = "--%v"
	optionType           = "(%v)"

	whitespace = "\r\n\t "

	indentStr = "  "
)

type helpFields struct {
	Indent      string
	Usage       string
	Path        string
	Tagline     string
	Arguments   string
	Options     string
	Synopsis    string
	Subcommands string
	Description string
	MoreHelp    bool
}

// TrimNewlines removes extra newlines from fields. This makes aligning
// commands easier. Below, the leading + tralining newlines are removed:
//	Synopsis: `
//	    ipfs config <key>          - Get value of <key>
//	    ipfs config <key> <value>  - Set value of <key> to <value>
//	    ipfs config --show         - Show config file
//	    ipfs config --edit         - Edit config file in $EDITOR
//	`
func (f *helpFields) TrimNewlines() {
	f.Path = strings.Trim(f.Path, "\n")
	f.Usage = strings.Trim(f.Usage, "\n")
	f.Tagline = strings.Trim(f.Tagline, "\n")
	f.Arguments = strings.Trim(f.Arguments, "\n")
	f.Options = strings.Trim(f.Options, "\n")
	f.Synopsis = strings.Trim(f.Synopsis, "\n")
	f.Subcommands = strings.Trim(f.Subcommands, "\n")
	f.Description = strings.Trim(f.Description, "\n")
}

// Indent adds whitespace the lines of fields.
func (f *helpFields) IndentAll() {
	indent := func(s string) string {
		if s == "" {
			return s
		}
		return indentString(s, indentStr)
	}

	f.Usage = indent(f.Usage)
	f.Arguments = indent(f.Arguments)
	f.Options = indent(f.Options)
	f.Synopsis = indent(f.Synopsis)
	f.Subcommands = indent(f.Subcommands)
	f.Description = indent(f.Description)
}

const longHelpFormat = `USAGE
{{.Usage}}

{{if .Synopsis}}SYNOPSIS
{{.Synopsis}}

{{end}}{{if .Arguments}}ARGUMENTS

{{.Arguments}}

{{end}}{{if .Options}}OPTIONS

{{.Options}}

{{end}}{{if .Description}}DESCRIPTION

{{.Description}}

{{end}}{{if .Subcommands}}SUBCOMMANDS
{{.Subcommands}}

{{.Indent}}For more information about each command, use:
{{.Indent}}'{{.Path}} <subcmd> --help'
{{end}}
`
const shortHelpFormat = `USAGE
{{.Usage}}
{{if .Synopsis}}
{{.Synopsis}}
{{end}}{{if .Description}}
{{.Description}}
{{end}}{{if .Subcommands}}
SUBCOMMANDS
{{.Subcommands}}
{{end}}{{if .MoreHelp}}
{{.Indent}}For more information about each command, use:
{{.Indent}}'{{.Path}} <subcmd> --help'
{{end}}
`

var longHelpTemplate *template.Template
var shortHelpTemplate *template.Template

func getTerminalWidth(out io.Writer) int {
	file, ok := out.(*os.File)
	if ok {
		if terminal.IsTerminal(int(file.Fd())) {
			width, _, err := terminal.GetSize(int(file.Fd()))
			if err == nil {
				return width
			}
		}
	}
	return defaultTerminalWidth
}

func init() {
	longHelpTemplate = template.Must(template.New("longHelp").Parse(longHelpFormat))
	shortHelpTemplate = template.Must(template.New("shortHelp").Parse(shortHelpFormat))
}

var ErrNoHelpRequested = errors.New("no help requested")

func HandleHelp(appName string, req *cmds.Request, out io.Writer) error {
	long, _ := req.Options[cmds.OptLongHelp].(bool)
	short, _ := req.Options[cmds.OptShortHelp].(bool)

	switch {
	case long:
		return LongHelp(appName, req.Root, req.Path, out)
	case short:
		return ShortHelp(appName, req.Root, req.Path, out)
	default:
		return ErrNoHelpRequested
	}
}

// LongHelp writes a formatted CLI helptext string to a Writer for the given command
func LongHelp(rootName string, root *cmds.Command, path []string, out io.Writer) error {
	cmd, err := root.Get(path)
	if err != nil {
		return err
	}

	pathStr := rootName
	if len(path) > 0 {
		pathStr += " " + strings.Join(path, " ")
	}

	fields := helpFields{
		Indent:      indentStr,
		Path:        pathStr,
		Tagline:     cmd.Helptext.Tagline,
		Arguments:   cmd.Helptext.Arguments,
		Options:     cmd.Helptext.Options,
		Synopsis:    cmd.Helptext.Synopsis,
		Subcommands: cmd.Helptext.Subcommands,
		Description: cmd.Helptext.ShortDescription,
		Usage:       cmd.Helptext.Usage,
		MoreHelp:    (cmd != root),
	}

	width := getTerminalWidth(out) - len(indentStr)

	if len(cmd.Helptext.LongDescription) > 0 {
		fields.Description = cmd.Helptext.LongDescription
	}

	// autogen fields that are empty
	if len(cmd.Helptext.Usage) > 0 {
		fields.Usage = cmd.Helptext.Usage
	} else {
		fields.Usage = commandUsageText(width, cmd, rootName, path)
	}
	if len(fields.Arguments) == 0 {
		fields.Arguments = strings.Join(argumentText(width, cmd), "\n")
	}
	if len(fields.Options) == 0 {
		fields.Options = strings.Join(optionText(width, cmd), "\n")
	}
	if len(fields.Subcommands) == 0 {
		fields.Subcommands = strings.Join(subcommandText(width, cmd, rootName, path), "\n")
	}
	if len(fields.Synopsis) == 0 {
		fields.Synopsis = generateSynopsis(width, cmd, pathStr)
	}

	// trim the extra newlines (see TrimNewlines doc)
	fields.TrimNewlines()

	// indent all fields that have been set
	fields.IndentAll()

	return longHelpTemplate.Execute(out, fields)
}

// ShortHelp writes a formatted CLI helptext string to a Writer for the given command
func ShortHelp(rootName string, root *cmds.Command, path []string, out io.Writer) error {
	cmd, err := root.Get(path)
	if err != nil {
		return err
	}

	// default cmd to root if there is no path
	if path == nil && cmd == nil {
		cmd = root
	}

	pathStr := rootName
	if len(path) > 0 {
		pathStr += " " + strings.Join(path, " ")
	}

	fields := helpFields{
		Indent:      indentStr,
		Path:        pathStr,
		Tagline:     cmd.Helptext.Tagline,
		Synopsis:    cmd.Helptext.Synopsis,
		Description: cmd.Helptext.ShortDescription,
		Subcommands: cmd.Helptext.Subcommands,
		MoreHelp:    (cmd != root),
	}

	width := getTerminalWidth(out) - len(indentStr)

	// autogen fields that are empty
	if len(cmd.Helptext.Usage) > 0 {
		fields.Usage = cmd.Helptext.Usage
	} else {
		fields.Usage = commandUsageText(width, cmd, rootName, path)
	}
	if len(fields.Subcommands) == 0 {
		fields.Subcommands = strings.Join(subcommandText(width, cmd, rootName, path), "\n")
	}
	if len(fields.Synopsis) == 0 {
		fields.Synopsis = generateSynopsis(width, cmd, pathStr)
	}

	// trim the extra newlines (see TrimNewlines doc)
	fields.TrimNewlines()

	// indent all fields that have been set
	fields.IndentAll()

	return shortHelpTemplate.Execute(out, fields)
}

func generateSynopsis(width int, cmd *cmds.Command, path string) string {
	res := path
	currentLineLength := len(res)
	appendText := func(text string) {
		if currentLineLength+len(text)+1 > width {
			res += "\n" + strings.Repeat(" ", len(path))
			currentLineLength = len(path)
		}
		currentLineLength += len(text) + 1
		res += " " + text
	}
	for _, opt := range cmd.Options {
		valopt, ok := cmd.Helptext.SynopsisOptionsValues[opt.Name()]
		if !ok {
			valopt = opt.Name()
		}
		sopt := ""
		for i, n := range opt.Names() {
			pre := "-"
			if len(n) > 1 {
				pre = "--"
			}
			if opt.Type() == cmds.Bool && opt.Default() == true {
				pre = "--"
				sopt = fmt.Sprintf("%s%s=false", pre, n)
				break
			} else {
				if i == 0 {
					if opt.Type() == cmds.Bool {
						sopt = fmt.Sprintf("%s%s", pre, n)
					} else {
						sopt = fmt.Sprintf("%s%s=<%s>", pre, n, valopt)
					}
				} else {
					sopt = fmt.Sprintf("%s | %s%s", sopt, pre, n)
				}
			}
		}
		appendText("[" + sopt + "]")
	}
	if len(cmd.Arguments) > 0 {
		appendText("[--]")
	}
	for _, arg := range cmd.Arguments {
		sarg := fmt.Sprintf("<%s>", arg.Name)
		if arg.Variadic {
			sarg = sarg + "..."
		}

		if !arg.Required {
			sarg = fmt.Sprintf("[%s]", sarg)
		}
		appendText(sarg)
	}
	return strings.Trim(res, " ")
}

func argumentText(width int, cmd *cmds.Command) []string {
	lines := make([]string, len(cmd.Arguments))

	for i, arg := range cmd.Arguments {
		lines[i] = argUsageText(arg)
	}
	lines = align(lines)
	for i, arg := range cmd.Arguments {
		lines[i] += " - "
		lines[i] = appendWrapped(lines[i], arg.Description, width)
	}

	return lines
}

func appendWrapped(prefix, text string, width int) string {
	offset := len(prefix)
	bWidth := width - offset

	text = strings.Trim(text, whitespace)
	// Minimum help-text width is 30 characters.
	if bWidth < 30 {
		prefix += text
		return prefix
	}

	for len(text) > bWidth {
		idx := strings.LastIndexAny(text[:bWidth], whitespace)
		if idx < 0 {
			idx = strings.IndexAny(text, whitespace)
		}
		if idx < 0 {
			break
		}
		prefix += text[:idx] + "\n" + strings.Repeat(" ", offset)
		text = strings.TrimLeft(text[idx:], whitespace)
	}
	prefix += text
	return prefix
}

func optionFlag(flag string) string {
	if len(flag) == 1 {
		return fmt.Sprintf(shortFlag, flag)
	} else {
		return fmt.Sprintf(longFlag, flag)
	}
}

func optionText(width int, cmd ...*cmds.Command) []string {
	// get a slice of the options we want to list out
	options := make([]cmds.Option, 0)
	for _, c := range cmd {
		for _, opt := range c.Options {
			options = append(options, opt)
		}
	}

	// add option names to output
	lines := make([]string, len(options))
	for i, opt := range options {
		flags := sortByLength(opt.Names())
		for j, f := range flags {
			flags[j] = optionFlag(f)
		}
		lines[i] = strings.Join(flags, ", ")
	}
	lines = align(lines)

	// add option types to output
	for i, opt := range options {
		lines[i] += "  " + fmt.Sprintf("%v", opt.Type())
	}
	lines = align(lines)

	// add option descriptions to output
	for i, opt := range options {
		lines[i] += " - "
		lines[i] = appendWrapped(lines[i], opt.Description(), width)
	}

	return lines
}

func subcommandText(width int, cmd *cmds.Command, rootName string, path []string) []string {
	prefix := fmt.Sprintf("%v %v", rootName, strings.Join(path, " "))
	if len(path) > 0 {
		prefix += " "
	}

	// Sorting fixes changing order bug #2981.
	sortedNames := make([]string, 0)
	for name := range cmd.Subcommands {
		sortedNames = append(sortedNames, name)
	}
	sort.Strings(sortedNames)

	subcmds := make([]*cmds.Command, len(cmd.Subcommands))
	lines := make([]string, len(cmd.Subcommands))

	for i, name := range sortedNames {
		sub := cmd.Subcommands[name]
		usage := usageText(sub)
		if len(usage) > 0 {
			usage = " " + usage
		}

		lines[i] = prefix + name + usage
		subcmds[i] = sub
	}

	lines = align(lines)
	for i, sub := range subcmds {
		lines[i] += " - "
		lines[i] = appendWrapped(lines[i], sub.Helptext.Tagline, width)
	}

	return lines
}

func commandUsageText(width int, cmd *cmds.Command, rootName string, path []string) string {
	text := fmt.Sprintf("%v %v", rootName, strings.Join(path, " "))
	argUsage := usageText(cmd)
	if len(argUsage) > 0 {
		text += " " + argUsage
	}
	text += " - "
	text = appendWrapped(text, cmd.Helptext.Tagline, width)
	return text
}

func usageText(cmd *cmds.Command) string {
	s := ""
	for i, arg := range cmd.Arguments {
		if i != 0 {
			s += " "
		}
		s += argUsageText(arg)
	}

	return s
}

func argUsageText(arg cmds.Argument) string {
	s := arg.Name

	if arg.Required {
		s = fmt.Sprintf(requiredArg, s)
	} else {
		s = fmt.Sprintf(optionalArg, s)
	}

	if arg.Variadic {
		s = fmt.Sprintf(variadicArg, s)
	}

	return s
}

func align(lines []string) []string {
	longest := 0
	for _, line := range lines {
		length := len(line)
		if length > longest {
			longest = length
		}
	}

	for i, line := range lines {
		length := len(line)
		if length > 0 {
			lines[i] += strings.Repeat(" ", longest-length)
		}
	}

	return lines
}

func indent(lines []string, prefix string) []string {
	for i, line := range lines {
		lines[i] = prefix + indentString(line, prefix)
	}
	return lines
}

func indentString(line string, prefix string) string {
	return prefix + strings.Replace(line, "\n", "\n"+prefix, -1)
}

type lengthSlice []string

func (ls lengthSlice) Len() int {
	return len(ls)
}
func (ls lengthSlice) Swap(a, b int) {
	ls[a], ls[b] = ls[b], ls[a]
}
func (ls lengthSlice) Less(a, b int) bool {
	return len(ls[a]) < len(ls[b])
}

func sortByLength(slice []string) []string {
	output := make(lengthSlice, len(slice))
	for i, val := range slice {
		output[i] = val
	}
	sort.Sort(output)
	return []string(output)
}
