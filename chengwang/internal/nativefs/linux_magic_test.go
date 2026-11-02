package nativefs

import "testing"

func TestClassifyLinuxMagicClosedSet(t *testing.T) {
	tests := []struct {
		magic int64
		class LinuxClass
		ok    bool
	}{
		{LinuxExt4Magic, LinuxExt4, true},
		{LinuxXFSMagic, LinuxXFS, true},
		{LinuxTmpfsMagic, LinuxTmpfs, true},
		{0, LinuxUnknown, false},
		{LinuxExt4Magic - 1, LinuxUnknown, false},
		{LinuxExt4Magic + 1, LinuxUnknown, false},
		{0x794c7630, LinuxUnknown, false}, // overlayfs
		{0x9123683e, LinuxUnknown, false}, // btrfs
		{-1, LinuxUnknown, false},
	}
	for _, test := range tests {
		class, ok := ClassifyLinuxMagic(test.magic)
		if class != test.class || ok != test.ok {
			t.Fatalf("magic %#x: got (%d,%v), want (%d,%v)", test.magic, class, ok, test.class, test.ok)
		}
	}
	if !PersistentDurabilityLane(LinuxExt4) || !PersistentDurabilityLane(LinuxXFS) {
		t.Fatal("ext4 and XFS must remain durability lanes")
	}
	if PersistentDurabilityLane(LinuxTmpfs) || PersistentDurabilityLane(LinuxUnknown) {
		t.Fatal("tmpfs and unknown filesystems cannot prove persistent durability")
	}
}
