package app

import "testing"

func TestComponentQuiescenceRejectsOrphanScriptsAndInterpreters(t *testing.T) {
	for _, p := range []componentProcess{
		{executable: "/opt/bin/opkg"},
		{executable: "/bin/busybox", args: []string{"/bin/sh", "/tmp/renamed-script"}},
		{executable: "/usr/bin/python3", args: []string{"python3", "-c", "script"}},
		{executable: "/tmp/synthetic.postinst"},
		{executable: "/bin/busybox", args: []string{"/opt/lib/opkg/info/test.postinst"}},
	} {
		if !packageProcess(p) {
			t.Fatal("package process not refused", p)
		}
	}
	if packageProcess(componentProcess{executable: "/opt/bin/razvilka", args: []string{"razvilka"}}) {
		t.Fatal("application misclassified")
	}
	if !componentProcessUses(componentProcess{executable: "/opt/bin/sing-box (deleted)"}, "sing-box") {
		t.Fatal("old unlinked process ignored")
	}
}
