rule Detect_CloseHandle: AntiDebug {
    meta: 
        description = "Detect CloseHandle as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "NtClose" fullword ascii
        $2 = "CloseHandle" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and any of them
}
