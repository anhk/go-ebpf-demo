package utils

import (
	"github.com/moby/sys/mount"
	"github.com/moby/sys/mountinfo"
)

func isMount(path string) bool {
	ok, err := mountinfo.Mounted(path)
	return ok && err == nil
}

func MountBPF() error {
	if isMount("/sys/fs/bpf") {
		return nil
	}

	return mount.Mount("bpffs", "/sys/fs/bpf", "bpf", "")
}
