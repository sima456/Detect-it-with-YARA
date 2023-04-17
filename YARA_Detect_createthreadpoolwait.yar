rule shellcode_injection_via_createthreadpoolwait {
  condition:
    pe.imports('VirtualAlloc') and pe.imports('CreateThreadpoolWait') and pe.imports('SetThreadpoolWait') and pe.imports('WaitForSingleObject')
}
