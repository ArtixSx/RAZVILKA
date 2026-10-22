package updatecheck

import (
	"context"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

// A component format is independent of node-history and self-update protocol.
// In particular reader4 must not turn schema0 into a general schema2 controller.
func TestComponentReaderFourOrdinaryAndBootstrapCapabilities(t *testing.T) {
	for _, schema := range []string{"0\n", "2\n"} {
		for _, required := range []int{2, 3, 4} {
			for _, reader := range []int{2, 3, 4, 5} {
				probe := func(_ context.Context, _, flag string) (string, error) {
					switch flag {
					case "-self-update-schema":
						return schema, nil
					case "-self-update-read-version":
						return "4\n", nil
					case "-component-update-schema":
						return strconv.Itoa(reader) + "\n", nil
					case "-node-history-read-version":
						return "3\n", nil
					default:
						return "1\n", nil
					}
				}
				ordinary := checkOrdinaryPreparationCapabilities(context.Background(), "sealed-candidate", 3, required, probe)
				bootstrap := checkExternalBootstrapCapabilities(context.Background(), "sealed-candidate", 3, required, probe)
				general := checkFileCapabilitiesForHistories(context.Background(), "sealed-candidate", 3, required, probe)
				compatible := reader >= required && reader <= 4
				if (ordinary == nil) != (compatible && schema == "0\n") || (bootstrap == nil) != (compatible && schema == "0\n") || (general == nil) != (compatible && schema == "2\n") {
					t.Fatal("component reader4 borrowed or lost another protocol capability", schema, required, reader, ordinary, bootstrap, general)
				}
			}
		}
	}
}

func TestComponentReaderFourAdmissionPreservesActualInitialInstallJournal(t *testing.T) {
	a := componentAdmissionFixture(t)
	a.currentReadVersion = 4
	// A canonical typed schema4 prepared intent is real retained metadata, not
	// an inspector stub or an installed-version DTO. No package effect is run.
	journal := []byte(`{"schema_version":4,"transaction_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","component":"nfqws2","phase":"initial-install-prepared","before_version":"absent","after_version":"1.3.1","updated_at":"2026-10-23T00:00:00Z","nfqws_initial_install":{"source_sha256":"28af67f8e192c838e007f23517b52b1f8c20d030cef5b971dfc93b7f21a79054","source_size":2382102,"derived_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","derived_size":100,"init_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","owner":"dddddddddddddddddddddddd","architecture":"arm64","status_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","installation_id":"ffffffffffffffffffffffffffffffff","sequence":1,"revision":7,"derivation":"inert-s51-and-root-owner-v1"},"package":"nfqws2-keenetic","package_file":"nfqws2-keenetic_1.3.1_razvilka-inert.ipk","package_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","configs":null,"supervision_version":1}`)
	retainedFile(t, a.stateRoot, "components/update-journal/current.json", journal)
	if required, err := components.RequiredRetainedManagedUpdateReadVersion(context.Background(), filepath.Join(a.stateRoot, "components")); err != nil || required != 4 {
		t.Fatal("fixture did not require the actual typed component reader4", required, err)
	}
	componentAdmissionOldController(t, a)
	a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) { return 4, nil }
	before, err := readDirectoryImage(context.Background(), a.stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.CheckReadable(context.Background()); err != nil {
		t.Fatal("current reader4 refused retained initial state", err)
	}
	if err := a.CheckWrite(context.Background(), 4); err != nil {
		t.Fatal("reader4 controllers refused actual component4 history", err)
	}
	a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) { return 3, nil }
	if err := a.CheckWrite(context.Background(), 4); err == nil {
		t.Fatal("retained reader3 was allowed to inherit component4 state")
	}
	a.currentReadVersion = 3
	if err := a.CheckReadable(context.Background()); err == nil {
		t.Fatal("reader3 accepted initial-install4 state")
	}
	after, err := readDirectoryImage(context.Background(), a.stateRoot)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("capability admission rewrote or cleared retained intent", err)
	}
}
