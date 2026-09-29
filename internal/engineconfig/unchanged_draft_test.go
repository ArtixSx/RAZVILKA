package engineconfig

import "testing"

// Reproduces the owner's router: the panel saved the owner's part of user.list
// without edits, dropping the managed block and the final line break, and the
// home page kept "changes are waiting" for a draft that changes nothing.
func TestUnchangedDraftIgnoresManagedBlockAndLineEnds(t *testing.T) {
	live := "youtube.com\naccount.riotgames.com\n" + ManagedListBegin + "\n# RAZVILKA INSTANCE 1\ndiscord.com\n" + ManagedListEnd + "\n"
	for name, draft := range map[string]string{
		"panel save":      "youtube.com\naccount.riotgames.com",
		"full copy":       live,
		"windows endings": "youtube.com\r\naccount.riotgames.com\r\n",
	} {
		if !unchangedDraft([]byte(draft), []byte(live)) {
			t.Fatalf("%s: unchanged draft reported as a change", name)
		}
	}
	for name, draft := range map[string]string{
		"added domain":   "youtube.com\naccount.riotgames.com\nexample.org",
		"removed domain": "youtube.com",
		"edited block":   "youtube.com\naccount.riotgames.com\n" + ManagedListBegin + "\nother.example\n" + ManagedListEnd + "\nlate.example\n",
		"empty":          "",
	} {
		if unchangedDraft([]byte(draft), []byte(live)) {
			t.Fatalf("%s: a real change was hidden", name)
		}
	}
}
