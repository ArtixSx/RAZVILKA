//go:build !linux

package updatecheck

import "context"

func (a *SelfUpdateFileAdapter) runFileCommand(context.Context, string, string) error {
	return ErrFileProtocol
}
func fileCommandInactive(context.Context, fileCommandReceipt) error    { return ErrFileProtocol }
func (a *SelfUpdateFileAdapter) filePanelAbsent(context.Context) error { return ErrFileProtocol }

func (a *SelfUpdateFileAdapter) oldPanelInactive(context.Context, string) error {
	return ErrFileProtocol
}
func (a *SelfUpdateFileAdapter) liveFileRuntime(context.Context, string, bool) error {
	return ErrFileProtocol
}
func (a *SelfUpdateFileAdapter) fileStartup(context.Context, string, string) error {
	return ErrFileProtocol
}

func (a *SelfUpdateFileAdapter) RuntimeQuiesceAuthority(context.Context, string, uint64, int) error {
	return ErrFileProtocol
}
func RunFileCommandHelper(string, string) int                                   { return 2 }
func RunFileCommandHelperWithStopGuard(string, string, SelfUpdateStopCheck) int { return 2 }
func RunFileCommandHelperWithAuthority(string, string, SelfUpdateStopCheck, SelfUpdateEffectAdmission, ...SelfUpdateRuntimeObservation) int {
	return 2
}
func fileHelperProcess() (fileProcess, error) { return fileProcess{}, ErrFileProtocol }
func fileProcessAt(int) (fileProcess, error)  { return fileProcess{}, ErrFileProtocol }
func (a *SelfUpdateFileAdapter) fileQuiescenceExcept(context.Context, string, string) error {
	return ErrFileProtocol
}
