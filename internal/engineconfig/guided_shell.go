package engineconfig

import (
	"fmt"
	"sort"
	"strings"
)

// This is a deliberately small, non-executing assignment reader, not a shell
// interpreter. Byte spans let the writer preserve comments, export prefixes,
// unrelated assignments and unchanged multiline strategies exactly.
type shellAssignment struct {
	key, value string
	start, end int
	quote      byte
}

func shellConfigError(content string, at int) error {
	return fmt.Errorf("Простой редактор не поддерживает shell-конструкцию в строке %d. Используйте экспертный режим; файл не изменён.", strings.Count(content[:at], "\n")+1)
}

func shellNameStart(c byte) bool {
	return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func shellNameChar(c byte) bool { return shellNameStart(c) || c >= '0' && c <= '9' }

func shellName(name string) bool {
	if name == "" || !shellNameStart(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !shellNameChar(name[i]) {
			return false
		}
	}
	return true
}

func shellNewline(content string, at int) int {
	if at < len(content) && content[at] == '\n' {
		return 1
	}
	if at+1 < len(content) && content[at] == '\r' && content[at+1] == '\n' {
		return 2
	}
	return 0
}

func scanShellAssignments(content string) ([]shellAssignment, error) {
	var out []shellAssignment
	seen := map[string]bool{}
	for pos := 0; pos < len(content); {
		for pos < len(content) && (content[pos] == ' ' || content[pos] == '\t') {
			pos++
		}
		if pos == len(content) {
			break
		}
		if n := shellNewline(content, pos); n > 0 {
			pos += n
			continue
		}
		if content[pos] == '#' {
			for pos < len(content) && content[pos] != '\n' {
				pos++
			}
			continue
		}
		lineStart := pos
		if strings.HasPrefix(content[pos:], "export") && pos+6 < len(content) && (content[pos+6] == ' ' || content[pos+6] == '\t') {
			pos += 6
			for pos < len(content) && (content[pos] == ' ' || content[pos] == '\t') {
				pos++
			}
		}
		keyStart := pos
		for pos < len(content) && shellNameChar(content[pos]) {
			pos++
		}
		key := content[keyStart:pos]
		if !shellName(key) || pos == len(content) || content[pos] != '=' || seen[key] {
			return nil, shellConfigError(content, lineStart)
		}
		seen[key] = true
		pos++
		a := shellAssignment{key: key, start: pos}
		if pos < len(content) && (content[pos] == '\'' || content[pos] == '"') {
			a.quote = content[pos]
			pos++
		}
		var value strings.Builder
		closed := a.quote == 0
		for pos < len(content) {
			c := content[pos]
			if a.quote != 0 && c == a.quote {
				pos++
				closed = true
				break
			}
			if a.quote == 0 && (c == ' ' || c == '\t' || shellNewline(content, pos) > 0) {
				break
			}
			if c == 0 || c == '\r' && shellNewline(content, pos) == 0 {
				return nil, shellConfigError(content, pos)
			}
			if a.quote != '\'' {
				if c == '`' || a.quote == 0 && strings.ContainsRune("'\";|&<>()", rune(c)) {
					return nil, shellConfigError(content, pos)
				}
				// Only ordinary named references are represented without evaluation.
				if c == '$' && (pos+1 == len(content) || !shellNameStart(content[pos+1])) {
					return nil, shellConfigError(content, pos)
				}
				if c == '\\' {
					if pos+1 == len(content) {
						return nil, shellConfigError(content, pos)
					}
					if n := shellNewline(content, pos+1); n > 0 {
						pos += n + 1 // POSIX line continuation has no value byte.
						continue
					}
					next := content[pos+1]
					// An escaped dollar would lose its literal/expanding distinction
					// in a plain form field; refuse instead of activating it on save.
					if next == '$' || next == '`' || next == 0 || next == '\r' {
						return nil, shellConfigError(content, pos)
					}
					if a.quote == 0 || next == '\\' || next == '"' {
						value.WriteByte(next)
						pos += 2
						continue
					}
				}
			}
			if n := shellNewline(content, pos); n > 0 {
				value.WriteByte('\n')
				pos += n
			} else {
				value.WriteByte(c)
				pos++
			}
		}
		if !closed {
			return nil, shellConfigError(content, lineStart)
		}
		a.value, a.end = value.String(), pos
		for pos < len(content) && (content[pos] == ' ' || content[pos] == '\t') {
			pos++
		}
		if pos < len(content) && content[pos] == '#' && pos > a.end {
			for pos < len(content) && content[pos] != '\n' {
				pos++
			}
		} else if pos < len(content) && shellNewline(content, pos) == 0 {
			return nil, shellConfigError(content, pos)
		}
		out = append(out, a)
	}
	return out, nil
}

func parseShellAssignments(content string) (map[string]string, error) {
	assignments, err := scanShellAssignments(content)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(assignments))
	for _, a := range assignments {
		out[a.key] = a.value
	}
	return out, nil
}

func shellGuidedChanges(content string, fields []GuidedField, values map[string]string, newFile bool) (map[string]string, error) {
	parsed, err := parseShellAssignments(content)
	if err != nil {
		return nil, err
	}
	if newFile {
		return values, nil
	}
	changed := make(map[string]string, len(values))
	for _, field := range fields {
		value, submitted := values[field.ID]
		if !submitted {
			continue
		}
		shown, present := parsed[field.ID]
		if !present {
			shown = field.Default
		}
		if strings.ReplaceAll(value, "\r\n", "\n") != shown {
			changed[field.ID] = value
		}
	}
	return changed, nil
}

func updateShellAssignments(content string, values map[string]string) (string, error) {
	assignments, err := scanShellAssignments(content)
	if err != nil {
		return "", err
	}
	newline := "\n"
	if strings.Contains(content, "\r\n") {
		newline = "\r\n"
	}
	var out strings.Builder
	seen := make(map[string]bool, len(assignments))
	last := 0
	for _, a := range assignments {
		seen[a.key] = true
		value, wanted := values[a.key]
		value = strings.ReplaceAll(value, "\r\n", "\n")
		if !wanted || value == a.value {
			continue
		}
		encoded, err := shellValue(value, a.quote)
		if err != nil {
			return "", err
		}
		out.WriteString(content[last:a.start])
		out.WriteString(strings.ReplaceAll(encoded, "\n", newline))
		last = a.end
	}
	out.WriteString(content[last:])
	var added []string
	for key := range values {
		if !shellName(key) {
			return "", shellConfigError("", 0)
		}
		if !seen[key] {
			added = append(added, key)
		}
	}
	sort.Strings(added)
	for _, key := range added {
		value, err := shellValue(strings.ReplaceAll(values[key], "\r\n", "\n"), 0)
		if err != nil {
			return "", err
		}
		if out.Len() > 0 && !strings.HasSuffix(out.String(), "\n") {
			out.WriteString(newline)
		}
		out.WriteString(key + "=" + strings.ReplaceAll(value, "\n", newline) + newline)
	}
	return out.String(), nil
}

func shellValue(value string, quote byte) (string, error) {
	if strings.ContainsAny(value, "\x00\r") {
		return "", shellConfigError("", 0)
	}
	if quote == '\'' {
		if strings.Contains(value, "'") {
			return "", shellConfigError("", 0)
		}
		return "'" + value + "'", nil
	}
	if !shellNamedReferences(value) {
		return "", shellConfigError("", 0)
	}
	return `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`, nil
}

func shellNamedReferences(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == '`' || value[i] == '$' && (i+1 == len(value) || !shellNameStart(value[i+1]) || i > 0 && value[i-1] == '\\') {
			return false
		}
	}
	return true
}
