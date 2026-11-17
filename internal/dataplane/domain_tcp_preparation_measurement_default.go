//go:build !linux || !razvilka_native_fixture

package dataplane

// Ordinary builds do not inspect contexts, writer state or clocks.
type domainTCPPreparationMeasurement struct{}

func domainTCPMeasurePreparation(*domainTCPCaptureExecutionResource, string, int) domainTCPPreparationMeasurement {
	return domainTCPPreparationMeasurement{}
}
func domainTCPMeasurePreparationCommand(*domainTCPCaptureEffectRunner, string) domainTCPPreparationMeasurement {
	return domainTCPPreparationMeasurement{}
}
func domainTCPMeasurePreparationSave(*policyEffectSession) domainTCPPreparationMeasurement {
	return domainTCPPreparationMeasurement{}
}
func (domainTCPPreparationMeasurement) end(err error) error { return err }
func (domainTCPPreparationMeasurement) bytes(data []byte, err error) ([]byte, error) {
	return data, err
}
