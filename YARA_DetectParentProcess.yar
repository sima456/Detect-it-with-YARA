rule ParentProcessEvasion
{
    strings:
        // Check for the CreateToolhelp32Snapshot() function call
        $create_snapshot = "CreateToolhelp32Snapshot"

        // Check for the Process32First() function call
        $process32_first = "Process32First"

        // Check for the Process32Next() function call
        $process32_next = "Process32Next"

        // Check for the GetCurrentProcessId() function call
        $get_current_pid = "GetCurrentProcessId"

    condition:
        // Check if all the required strings are present in the code
        all of them
}
