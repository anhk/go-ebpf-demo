package main

import (
	"go_ebpf_demo/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --target bpfel ebpf ebpf/proxy.c -- -I ../inc

func main() {
	utils.Must(rlimit.RemoveMemlock())
	var objs = ebpfObjects{}
	utils.Must(loadEbpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf"},
	}))
	defer objs.Close()

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.ebpfPrograms.SockConnect4,
	})
	utils.Must(err)
	defer l.Close()

	l2, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.SockEgress,
	})
	utils.Must(err)
	defer l2.Close()

	l3, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: objs.SockIngress,
	})
	utils.Must(err)
	defer l3.Close()

	go utils.TraceEBPF()
	utils.WaitInterrupt()
}
