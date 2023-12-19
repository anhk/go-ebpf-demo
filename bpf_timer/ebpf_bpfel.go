// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || loong64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type ebpfMapElem struct {
	Counter int32
	_       [4]byte
	Timer   struct{ _ [16]byte }
}

// loadEbpf returns the embedded CollectionSpec for ebpf.
func loadEbpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_EbpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load ebpf: %w", err)
	}

	return spec, err
}

// loadEbpfObjects loads ebpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*ebpfObjects
//	*ebpfPrograms
//	*ebpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadEbpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadEbpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// ebpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ebpfSpecs struct {
	ebpfProgramSpecs
	ebpfMapSpecs
}

// ebpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ebpfProgramSpecs struct {
	SockConnect4 *ebpf.ProgramSpec `ebpf:"sock_connect4"`
}

// ebpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ebpfMapSpecs struct {
	Hmap *ebpf.MapSpec `ebpf:"hmap"`
}

// ebpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadEbpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type ebpfObjects struct {
	ebpfPrograms
	ebpfMaps
}

func (o *ebpfObjects) Close() error {
	return _EbpfClose(
		&o.ebpfPrograms,
		&o.ebpfMaps,
	)
}

// ebpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadEbpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type ebpfMaps struct {
	Hmap *ebpf.Map `ebpf:"hmap"`
}

func (m *ebpfMaps) Close() error {
	return _EbpfClose(
		m.Hmap,
	)
}

// ebpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadEbpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type ebpfPrograms struct {
	SockConnect4 *ebpf.Program `ebpf:"sock_connect4"`
}

func (p *ebpfPrograms) Close() error {
	return _EbpfClose(
		p.SockConnect4,
	)
}

func _EbpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed ebpf_bpfel.o
var _EbpfBytes []byte
