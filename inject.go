package dllinjection

import (
	"errors"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
)

func Inject(processName, dllPath string) error {
	processes, err := processes()
	if err != nil {
		return err
	}

	var pid uint32
	for _, process := range processes {
		if process.executable == processName {
			pid = uint32(process.processID)
			break
		}
	}

	if pid == 0 {
		return errors.New("process not found")
	}

	const PROCESS_ALL_ACCESS = 0x001F0FFF
	processHandle, err := syscall.OpenProcess(PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(processHandle)

	dllPathAbs, err := filepath.Abs(dllPath)
	if err != nil {
		return err
	}

	dllPathRemoteAddr, err := virtualAllocEx(processHandle, len(dllPathAbs)+1)
	if err != nil {
		return err
	}

	err = writeProcessMemoryString(processHandle, dllPathRemoteAddr, dllPathAbs)
	if err != nil {
		return err
	}

	moduleKernel, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		return err
	}

	loadLibraryAddr, err := syscall.GetProcAddress(moduleKernel, "LoadLibraryA")
	if err != nil {
		return err
	}

	return createRemoteThreadDLL(processHandle, loadLibraryAddr, dllPathRemoteAddr)
}

func virtualAllocEx(processHandle syscall.Handle, size int) (uintptr, error) {
	const MEM_COMMIT = 0x1000
	const MEM_RESERVE = 0x2000
	const PAGE_READWRITE = 0x00000004

	addr, _, err := procVirtualAllocEx.Call(
		uintptr(processHandle),
		uintptr(0),
		uintptr(size),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if addr == 0 {
		return 0, err
	}

	return addr, nil
}

func writeProcessMemoryString(processHandle syscall.Handle, dstAddr uintptr, str string) error {
	strPointer, err := syscall.BytePtrFromString(str)
	if err != nil {
		return err
	}

	success, _, err := procWriteProcessMemory.Call(
		uintptr(processHandle),
		dstAddr,
		uintptr(unsafe.Pointer(strPointer)),
		uintptr(len(str)+1),
		uintptr(0),
	)
	if success == 0 {
		return err
	}

	return nil
}

func createRemoteThreadDLL(processHandle syscall.Handle, loadLibraryAddr uintptr, dllPathRemoteAddr uintptr) error {
	remoteThread, _, err := procCreateRemoteThread.Call(
		uintptr(processHandle),
		uintptr(0),
		uintptr(0),
		loadLibraryAddr,
		dllPathRemoteAddr,
		uintptr(0),
		uintptr(0),
	)
	if remoteThread == 0 {
		return err
	}

	return nil
}

type processInfo struct {
	processID       int
	parentProcessID int
	executable      string
}

func processes() ([]processInfo, error) {
	const TH32CS_SNAPPROCESS = 0x00000002
	handle, err := syscall.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(handle)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = syscall.Process32First(handle, &entry)
	if err != nil {
		return nil, err
	}

	results := make([]processInfo, 0, 50)
	for {
		results = append(results, newProcessInfo(&entry))

		err = syscall.Process32Next(handle, &entry)
		if err != nil {
			if err == syscall.ERROR_NO_MORE_FILES {
				return results, nil
			}
			return nil, err
		}
	}
}

func newProcessInfo(e *syscall.ProcessEntry32) processInfo {
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}

	return processInfo{
		processID:       int(e.ProcessID),
		parentProcessID: int(e.ParentProcessID),
		executable:      syscall.UTF16ToString(e.ExeFile[:end]),
	}
}
