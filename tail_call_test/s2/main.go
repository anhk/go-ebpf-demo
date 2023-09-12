package main

import (
	"fmt"
	"go_ebpf_demo/utils"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf/s2.c -- -I ../../inc -I ../cinc

func main() {
	utils.Must(rlimit.RemoveMemlock())

	var objs ebpfObjects
	utils.Must(loadEbpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/a/"},
	}))
	defer objs.Close()

	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tj_map", &ebpf.LoadPinOptions{})

	utils.Must(err)

	info, err := objs.ebpfPrograms.SockConnect444.Info()
	utils.Must(err)

	id, _ := info.ID()
	fmt.Printf("id: %v\n", id)

	key := uint32(1)
	utils.Must(m.Update(
		unsafe.Pointer(&key),
		objs.ebpfPrograms.SockConnect444,
		ebpf.UpdateAny))

	go utils.TraceEBPF()

	utils.WaitInterrupt()
	m.Delete(&key)
}
