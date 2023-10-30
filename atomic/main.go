package main

import (
	"go_ebpf_demo/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel ebpf ebpf/atomic.c -- -I ../inc

func main() {
	utils.Must(rlimit.RemoveMemlock())

	var objs = ebpfObjects{}
	utils.Must(loadEbpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/"},
	}))
	defer objs.Close()

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.SockConnect4,
	})
	utils.Must(err)
	defer l.Close()

	l.Pin("/sys/fs/bpf/connect46")

	go utils.TraceEBPF()
	utils.WaitInterrupt()
}
