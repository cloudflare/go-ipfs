//+build windows

package cli

import (
	"syscall"
)

const (
	invalid_file_handle     syscall.Errno = 0x6 // console output is not buffered on this platform
	invalid_handle_function syscall.Errno = 0x1 // this is specifically returned when NUL is the FlushFileBuffers target
)

func isErrnoNotSupported(err error) bool {
	switch err {
	case syscall.EINVAL, syscall.ENOTSUP, syscall.ENOTTY, invalid_file_handle, invalid_handle_function:
		return true
	}
	return false
}
