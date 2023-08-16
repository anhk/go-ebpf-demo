package main

import (
	"go_ebpf_demo/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf/cgroup-egress.c -- -I ../inc

func main() {
	utils.Must(rlimit.RemoveMemlock())
	utils.Must(utils.MountBPF())

	var objs ebpfObjects
	utils.Must(loadEbpfObjects(&objs, &ebpf.CollectionOptions{}))
	defer objs.Close()

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: objs.CgroupIngress,
	})
	utils.Must(err)
	defer l.Close()

	l2, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.CgroupEgress,
	})
	utils.Must(err)
	defer l2.Close()

	go utils.TraceEBPF()
	utils.WaitInterrupt()
}
