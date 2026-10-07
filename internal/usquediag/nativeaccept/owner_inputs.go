package nativeaccept

import "errors"

// ValidateOwnerRequest exposes the same pure front-door predicates to the
// concrete retained owner. It does not read assets or issue execution authority.
func ValidateOwnerRequest(r Request) error {
	if code := validate(r); code != "" {
		return errors.New(code)
	}
	return nil
}
