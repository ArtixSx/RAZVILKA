package engineconfig

import (
	"errors"
	"strconv"
	"strings"
)

var ErrNFQWSStartupArguments = errors.New("NFQWS2 startup arguments cannot be reviewed without executing configuration")

// NFQWSStartupArguments mirrors the 1.3.1 package's _startup_args assembly.
// It reads assignments as data, never sources shell or calls the init script.
// This is parameter material only: neither a list-only policy nor Lua/packet
// compatibility is established by assembling or dry-running this command.
func NFQWSStartupArguments(content string, leadingProfiles []string) ([]string, error) {
	fields, err := nfqwsStartupFields(content)
	if err != nil {
		return nil, err
	}
	return nfqwsStartupArguments(fields, leadingProfiles)
}

// NFQWSRunningConfigMatches refuses a stale or executable .conf.run overlay.
// Stock restart sources it before stop; only its generated runtime fields are
// admitted and every argv-affecting value must agree with the reviewed main.
func NFQWSRunningConfigMatches(content, running string) error {
	base, err := nfqwsStartupFields(content)
	if err != nil {
		return err
	}
	assignments, err := scanShellAssignments(running)
	if err != nil {
		return ErrNFQWSStartupArguments
	}
	for _, a := range assignments {
		switch a.key {
		case "ISP_INTERFACE", "IPV6_ENABLED", "NFQUEUE_NUM":
			if a.value != base[a.key] {
				return ErrNFQWSStartupArguments
			}
		case "TCP_PORTS", "UDP_PORTS", "POLICY_NAME", "POLICY_EXCLUDE", "POLICY_MARK":
		default:
			return ErrNFQWSStartupArguments
		}
		if strings.ContainsAny(a.value, "$`\\") {
			return ErrNFQWSStartupArguments
		}
	}
	return nil
}

func nfqwsStartupFields(content string) (map[string]string, error) {
	assignments, err := scanShellAssignments(content)
	if err != nil {
		return nil, ErrNFQWSStartupArguments
	}
	fields := map[string]string{}
	for _, assignment := range assignments {
		switch assignment.key {
		case "NFQWS_BIN", "CONFFILE", "PIDFILE", "PATH", "IFS", "ENV", "BASH_ENV", "LD_PRELOAD", "LD_LIBRARY_PATH":
			return nil, ErrNFQWSStartupArguments
		}
		value := assignment.value
		if assignment.quote != '\'' {
			var expanded strings.Builder
			for i := 0; i < len(value); {
				if value[i] != '$' {
					expanded.WriteByte(value[i])
					i++
					continue
				}
				end := i + 1
				for end < len(value) && shellNameChar(value[end]) {
					end++
				}
				replacement, known := fields[value[i+1:end]]
				if !known {
					return nil, ErrNFQWSStartupArguments
				}
				expanded.WriteString(replacement)
				i = end
			}
			value = expanded.String()
		}
		if len(value) > 48<<10 {
			return nil, ErrNFQWSStartupArguments
		}
		fields[assignment.key] = value
	}
	return fields, nil
}

func nfqwsStartupArguments(fields map[string]string, leadingProfiles []string) ([]string, error) {
	queue, err := strconv.Atoi(fields["NFQUEUE_NUM"])
	if err != nil || queue < 1 || queue > 65535 || fields["USER"] != "nobody" {
		return nil, ErrNFQWSStartupArguments
	}
	args := []string{"--user=nobody", "--qnum=" + strconv.Itoa(queue)}
	if !strings.Contains(fields["NFQWS_BASE_ARGS"], "--fastpath-workaround=") {
		args = append(args, "--fastpath-workaround=auto")
	}
	args = append(args, strings.Fields(fields["NFQWS_BASE_ARGS"])...)
	if len(strings.Fields(fields["ISP_INTERFACE"])) > 1 {
		args = append(args, "--bind-fix4")
		if fields["IPV6_ENABLED"] != "" && fields["IPV6_ENABLED"] != "0" {
			args = append(args, "--bind-fix6")
		}
	}
	// Logging adds no parsing semantics and may open/write a path during a
	// future native mode. Never include it in this no-effect dry-run command.
	if fields["LOG_LEVEL"] != "" && fields["LOG_LEVEL"] != "0" {
		return nil, ErrNFQWSStartupArguments
	}
	for _, key := range []string{"NFQWS_BASE_ARGS", "NFQWS_ARGS", "NFQWS_ARGS_QUIC", "NFQWS_ARGS_UDP", "NFQWS_EXTRA_ARGS", "NFQWS_ARGS_IPSET"} {
		if strings.Contains(fields[key], "--new") {
			return nil, ErrNFQWSStartupArguments
		}
	}
	custom := append([]string(nil), leadingProfiles...)
	if fields["NFQWS_ARGS_CUSTOM"] != "" {
		if len(custom) != 0 {
			custom = append(custom, "--new")
		}
		custom = append(custom, strings.Fields(fields["NFQWS_ARGS_CUSTOM"])...)
	}
	if len(custom) != 0 {
		args = append(args, append(custom, "--new")...)
	}
	if fields["NFQWS_ARGS_UDP"] != "" {
		args = append(args, append(strings.Fields(fields["NFQWS_ARGS_UDP"]), "--new")...)
	}
	if fields["NFQWS_ARGS_QUIC"] != "" {
		args = appendNFQWSProfile(args, fields["NFQWS_ARGS_QUIC"], fields["NFQWS_ARGS_IPSET"], fields["NFQWS_EXTRA_ARGS"])
		args = append(args, "--new")
	}
	args = appendNFQWSProfile(args, fields["NFQWS_ARGS"], fields["NFQWS_ARGS_IPSET"], fields["NFQWS_EXTRA_ARGS"])
	if len(args) > 256 || len(strings.Join(args, " ")) > 48<<10 {
		return nil, ErrNFQWSStartupArguments
	}
	for _, argument := range args {
		if !strings.HasPrefix(argument, "--") || strings.ContainsAny(argument, "\x00\r\n`$'\"\\*?[]") {
			return nil, ErrNFQWSStartupArguments
		}
		name, _, _ := strings.Cut(argument, "=")
		switch name {
		case "--daemon", "--pidfile", "--dry-run", "--intercept", "--debug":
			return nil, ErrNFQWSStartupArguments
		}
	}
	return args, nil
}

func appendNFQWSProfile(args []string, strategy, ipset, extra string) []string {
	if ipset != "" {
		args = append(args, strings.Fields(strategy)...)
		args = append(args, strings.Fields(ipset)...)
		args = append(args, "--ipset-ip=0.0.0.0", "--new")
	}
	args = append(args, strings.Fields(strategy)...)
	return append(args, strings.Fields(extra)...)
}
