package utils

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
)

func Must(e any) {
	if e != nil {
		fmt.Printf("%s\n", e)
		fmt.Printf("%s\n", debug.Stack())
		os.Exit(-1)
	}
}

func TraceEBPF() {
	f, _ := os.OpenFile("/sys/kernel/debug/tracing/trace_pipe", os.O_RDONLY, os.ModePerm)
	defer f.Close()
	reader := bufio.NewReader(f)
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		fmt.Println(string(line))
	}
}

func Pointer[T any](v T) *T {
	return &v
}

func WaitInterrupt() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
}
