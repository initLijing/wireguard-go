// Code generated by 'go generate'; DO NOT EDIT.

package resource

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procFindResourceW  = modkernel32.NewProc("FindResourceW")
	procSizeofResource = modkernel32.NewProc("SizeofResource")
	procLoadResource   = modkernel32.NewProc("LoadResource")
	procLockResource   = modkernel32.NewProc("LockResource")
)

func findResource(module windows.Handle, name *uint16, resType *uint16) (resInfo windows.Handle, err error) {
	r0, _, e1 := syscall.Syscall(procFindResourceW.Addr(), 3, uintptr(module), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(resType)))
	resInfo = windows.Handle(r0)
	if resInfo == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func Sizeof(module windows.Handle, resInfo windows.Handle) (size uint32, err error) {
	r0, _, e1 := syscall.Syscall(procSizeofResource.Addr(), 2, uintptr(module), uintptr(resInfo), 0)
	size = uint32(r0)
	if size == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func Load(module windows.Handle, resInfo windows.Handle) (resData windows.Handle, err error) {
	r0, _, e1 := syscall.Syscall(procLoadResource.Addr(), 2, uintptr(module), uintptr(resInfo), 0)
	resData = windows.Handle(r0)
	if resData == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func Lock(resData windows.Handle) (addr uintptr, err error) {
	r0, _, e1 := syscall.Syscall(procLockResource.Addr(), 1, uintptr(resData), 0, 0)
	addr = uintptr(r0)
	if addr == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}
