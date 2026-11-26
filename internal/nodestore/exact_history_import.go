package nodestore

// RequiredImportReadVersion inspects fully accepted incoming canonical node
// material before a trusted caller's write admission. It performs no I/O, takes
// no Store lock, and returns no identities or secrets. RAW/legacy imports need
// reader 1; unchecked XHTTP needs 3. Existing/retained state must be inspected by
// the owning admission guard, independently of this incoming-material minimum.
func RequiredImportReadVersion(raw string, acceptPartial bool) (int, error) {
	materials, err := parseImportMaterials(raw, acceptPartial)
	if err != nil {
		return 0, err
	}
	required := 1
	for _, material := range materials {
		if version := requiredOutboundReadVersion(material); version > required {
			required = version
		}
		clear(material)
	}
	return required, nil
}
