package main

import (
	"regexp"
	"strings"
	"testing"
)

func TestAccountPasswordFieldsAcceptAnyNonemptyValue(t *testing.T) {
	data, err := embedded.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"setupPassword", "setupPasswordRepeat", "loginPassword", "recoveryPassword", "recoveryPasswordRepeat", "currentPassword", "newPassword", "newPasswordRepeat"} {
		fields := regexp.MustCompile(`<input\b[^>]*\bid="`+regexp.QuoteMeta(id)+`"[^>]*>`).FindAllString(string(data), -1)
		if len(fields) != 1 {
			t.Fatalf("expected exactly one account password field %s", id)
		}
		if !strings.Contains(fields[0], `type="password"`) || !strings.Contains(fields[0], `required`) || strings.Contains(fields[0], `minlength`) || strings.Contains(fields[0], `pattern=`) {
			t.Fatalf("field %s imposes a password minimum/composition rule or allows empty input", id)
		}
	}
}
