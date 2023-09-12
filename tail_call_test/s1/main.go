package main

import (
	"fmt"
	"go_ebpf_demo/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf/s1.c -- -I ../../inc -I ../cinc

func main() {
	utils.Must(rlimit.RemoveMemlock())

	var objs ebpfObjects
	utils.Must(loadEbpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/"},
	}))
	defer objs.Close()
	utils.Must(objs.ebpfMaps.TjMap.Pin("/sys/fs/bpf/tj_map"))

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.SockConnect4,
	})
	utils.Must(err)
	defer l.Close()

	l.Pin("/sys/fs/bpf/connect46")

	var key uint32
	var value any
	iter := objs.ebpfMaps.TjMap.Iterate()
	for iter.Next(&key, &value) {
		fmt.Printf("key: %d , value: %T", key, value)
	}
	utils.TraceEBPF()
}
