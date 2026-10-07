package netidentity

import "slices"

type checks struct {
	ThreadLocked, ProcRootVerified, SelfLinksMatch, AnchoredWalkVerified bool
	SameProcMount, FreshPositionZero, RawDirentsValid, DotsPresent       bool
	SamePIDTID, SameTaskStart, SameBoot, SameKernelRelease               bool
	SameMountLayout, HeldDescriptorsStable, ReopenedPathStable           bool
}
type observation struct {
	KernelRelease, Machine, BootID                                                 string
	Names, PIDNames                                                                []string
	Inode                                                                          uint64
	NetPresent, MntPresent, DirectoryComplete, DTUnknownObserved, ObservationValid bool
	Checks                                                                         checks
}

func identityFromObservation(o observation, p *reviewedProfile) (Identity, error) {
	c := o.Checks
	if !o.ObservationValid || !o.DirectoryComplete || !o.MntPresent ||
		!c.ThreadLocked || !c.ProcRootVerified || !c.SelfLinksMatch || !c.AnchoredWalkVerified ||
		!c.SameProcMount || !c.FreshPositionZero || !c.RawDirentsValid || !c.DotsPresent ||
		!c.SamePIDTID || !c.SameTaskStart || !c.SameBoot || !c.SameKernelRelease ||
		!c.SameMountLayout || !c.HeldDescriptorsStable || !c.ReopenedPathStable ||
		!validBoot(o.BootID) || o.KernelRelease == "" || o.Machine == "" ||
		!slices.Equal(o.Names, o.PIDNames) || len(o.Names) == 0 || len(o.Names) > maxNames ||
		o.NetPresent != slices.Contains(o.Names, "net") || !slices.Contains(o.Names, "mnt") {
		return Identity{}, ErrUnknown
	}
	seen := map[string]bool{}
	for _, name := range o.Names {
		if !validNamespaceName(name) || seen[name] {
			return Identity{}, ErrUnknown
		}
		seen[name] = true
	}
	v := Identity{Version: Version, BootID: o.BootID}
	if o.NetPresent {
		v.Kind, v.Inode = ProcNetInode, o.Inode
	} else {
		if p == nil || p.hash() != nc1812Profile().hash() || o.KernelRelease != p.KernelRelease || o.Machine != p.Machine || o.Inode != 0 {
			return Identity{}, ErrUnknown
		}
		v.Kind, v.PlatformReviewSHA256 = ReviewedSingleInitNet, p.hash()
	}
	if err := v.Validate(); err != nil {
		return Identity{}, err
	}
	return v, nil
}
func validNamespaceName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, b := range []byte(name) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_') {
			return false
		}
	}
	return true
}
