package updatecheck

import (
	"encoding/json"
	"os"
)

type fileHelperIdentity struct {
	Schema   int         `json:"schema"`
	ID       string      `json:"id"`
	Process  fileProcess `json:"process"`
	OldPanel fileProcess `json:"old_panel"`
}

func sealFileHelperIdentity(a *SelfUpdateFileAdapter, id string, review fileReview) error {
	process, err := fileHelperProcess()
	if err != nil || process.PID != os.Getpid() || process.ExecutableSHA256 != reviewedHelperSHA(review) {
		return ErrFileProtocol
	}
	record, err := readAdapterRecord(a.directory, id)
	if err != nil {
		return err
	}
	oldPanel, err := fileProcessAt(record.ParentPID)
	if err != nil || oldPanel.ExecutableSHA256 != review.OldExecutableSHA256 {
		return ErrFileProtocol
	}
	if review.PreparationParent != nil && oldPanel != *review.PreparationParent {
		return ErrFileProtocol
	}
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := json.Marshal(fileHelperIdentity{selfUpdateProtocolSchema, id, process, oldPanel})
	if err != nil {
		return err
	}
	f, err := root.OpenFile("helper.identity.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return syncSelfUpdateDirectory(root)
}

func (a *SelfUpdateFileAdapter) helperIdentity(id string, review fileReview) (fileHelperIdentity, error) {
	identity, err := a.readHelperIdentity(id, review)
	if err != nil {
		return identity, err
	}
	record, err := readAdapterRecord(a.directory, id)
	if err != nil {
		return identity, err
	}
	return bindHelperIdentity(id, review, record, identity)
}

// Retained jobs bind their identity to the verified retained helper record.
// The current record may already describe a later, pending preparation.
func (a *SelfUpdateFileAdapter) helperIdentityForRecord(id string, review fileReview, record updateRecord) (fileHelperIdentity, error) {
	identity, err := a.readHelperIdentity(id, review)
	if err != nil {
		return identity, err
	}
	return bindHelperIdentity(id, review, record, identity)
}

func bindHelperIdentity(id string, review fileReview, record updateRecord, identity fileHelperIdentity) (fileHelperIdentity, error) {
	if review.ID != id || record.Owner != updaterOwner || record.Job.ID != id || record.Job.HelperPID != identity.Process.PID || record.ParentPID != identity.OldPanel.PID || review.PreparationParent != nil && *review.PreparationParent != identity.OldPanel {
		return identity, ErrFileProtocol
	}
	return identity, nil
}

func (a *SelfUpdateFileAdapter) readHelperIdentity(id string, review fileReview) (fileHelperIdentity, error) {
	var identity fileHelperIdentity
	root, err := a.commandRoot(id)
	if err != nil {
		return identity, err
	}
	defer root.Close()
	data, err := root.ReadLimited("helper.identity.json", 4096)
	if err != nil {
		return identity, err
	}
	if decodeFileProtocol(data, &identity) != nil || identity.Schema != selfUpdateProtocolSchema || identity.ID != id || !validFileProcess(identity.Process) || !validFileProcess(identity.OldPanel) || identity.Process.ExecutableSHA256 != reviewedHelperSHA(review) || identity.OldPanel.ExecutableSHA256 != review.OldExecutableSHA256 || identity.Process.Boot != identity.OldPanel.Boot {
		return identity, ErrFileProtocol
	}
	return identity, nil
}
