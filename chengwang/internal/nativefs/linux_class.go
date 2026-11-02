package nativefs

// LinuxClass is the closed native-filesystem admission result. Filesystem
// magic values and classification are generated from the immutable legacy
// owner; this handwritten file deliberately contains no magic literal.
type LinuxClass uint8

const (
	LinuxUnknown LinuxClass = iota
	LinuxExt4
	LinuxXFS
	LinuxTmpfs
)

// PersistentDurabilityLane distinguishes ext4/XFS evidence from tmpfs-only
// syscall and recovery semantics.
func PersistentDurabilityLane(class LinuxClass) bool {
	return class == LinuxExt4 || class == LinuxXFS
}
