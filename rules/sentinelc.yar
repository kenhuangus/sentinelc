// SentinelC YARA-subset rules. Generic, illustrative detections for the
// targeted file scan (--scan-path). Supported subset: text strings (ascii,
// wide, nocase), hex patterns with ?? wildcards, and conditions
// (any/all/N of them, or simple $a and/or $b). Tune to your environment.

rule EICAR_Test_File {
    strings:
        $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        any of them
}

rule Obfuscated_PowerShell {
    strings:
        $a = "DownloadString" nocase
        $b = "FromBase64String" nocase
        $c = "Invoke-Expression" nocase
        $d = "IEX(" nocase
        $e = "-EncodedCommand" nocase
        $f = "-w hidden" nocase
        $g = "-nop" nocase
    condition:
        2 of them
}

rule Reflective_Injection_Markers {
    strings:
        $a = "ReflectiveLoader" ascii nocase
        $b = "VirtualAllocEx" ascii
        $c = "CreateRemoteThread" ascii
        $d = "WriteProcessMemory" ascii
        $e = "NtUnmapViewOfSection" ascii
    condition:
        2 of them
}

rule Script_Dropper_Markers {
    strings:
        $a = "WScript.Shell" nocase
        $b = "powershell" nocase
        $c = "cmd.exe /c" nocase
        $d = "curl" nocase
        $e = "certutil" nocase
        $f = "bitsadmin" nocase
        $url = "http" nocase
    condition:
        3 of them
}

rule Embedded_PE_In_Nonexe {
    // an MZ...PE header pair near the top of a non-EXE file is a common dropper
    // shape (payload embedded in a script/document). Tune if you store PEs.
    strings:
        $mz = { 4D 5A 90 00 }
        $pe = "This program cannot be run in DOS mode"
    condition:
        all of them
}
