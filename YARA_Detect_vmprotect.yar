rule VMProtect_v125_PolyTech_additional: PEiD
{
    strings:
        $a = { 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 A5 06 00 00 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }
    condition:
        $a at pe.entry_point

}
rule VMProtect246_PolyTech: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? 60 C7 ?? ?? ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 60 E8 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_v125_PolyTech: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 52 }
        $b = { 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 A5 06 00 00 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }
        $c = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
rule VMProtect_07x_08_PolyTech_additional: PEiD
{
    strings:
        $a = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 76 20 30 2E 38 20 28 43 29 20 50 6F 6C 79 54 65 63 68 20 5D }
    condition:
        $a at pe.entry_point

}
rule VMProtect_106107_PolyTech_additional: PEiD
{
    strings:
        $a = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_V1X_PolyTech: PEiD
{
    strings:
        $a = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_0x_PolyTech: PEiD
{
    strings:
        $a = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_180_phpbb3: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? A8 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_V1X_PolyTech_additional: PEiD
{
    strings:
        $a = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_1704_phpbb3: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_0x_PolyTech_additional: PEiD
{
    strings:
        $a = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_106107_PolyTech: PEiD
{
    strings:
        $a = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }
    condition:
        $a at pe.entry_point

}
rule VMProtect_07x_08_PolyTech: PEiD
{
    strings:
        $a = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 76 20 30 2E 38 20 28 43 29 20 50 6F 6C 79 54 65 63 68 20 5D }
    condition:
        $a at pe.entry_point

}
rule _VMProtect_v125_PolyTech_additional: PEiD
{
    strings:
        $a = { 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 A5 06 00 00 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }
    condition:
        $a at pe.entry_point

}
rule _VMProtect_v125_PolyTech: PEiD
{
    strings:
        $a = { 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 A5 06 00 00 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }
        $b = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 56 52 56 51 9C 55 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 34 85 A7 72 45 00 C3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
