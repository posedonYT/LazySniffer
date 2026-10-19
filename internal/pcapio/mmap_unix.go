//go:build unix

package pcapio

import (
	"os"
	"syscall"
)

func mmap(f *os.File, size int64) ([]byte, error) {
	return syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
}

func munmap(b []byte) { _ = syscall.Munmap(b) }
