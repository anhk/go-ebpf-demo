package main

import (
	"go_ebpf_demo/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 ebpf ebpf/tos.c -- -I ../inc

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
	defer l.Unpin()

	// l2, err := link.AttachCgroup(link.CgroupOptions{
	// 	Path:    "/sys/fs/cgroup",
	// 	Attach:  ebpf.AttachCGroupInet6Bind,
	// 	Program: objs.SockBind6,
	// })
	// utils.Must(err)
	// defer l2.Close()

	// l3, err := link.AttachCgroup(link.CgroupOptions{
	// 	Path:    "/sys/fs/cgroup",
	// 	Attach:  ebpf.AttachCGroupInet4PostBind,
	// 	Program: objs.SockPostBind4,
	// })
	// utils.Must(err)
	// defer l3.Close()

	go utils.TraceEBPF()
	utils.WaitInterrupt()
}
