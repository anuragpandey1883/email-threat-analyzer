rule Suspicious_PowerShell_Indicators
{
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "downloadstring" nocase
    condition:
        2 of them
}

rule Suspicious_Office_Macro_Indicators
{
    strings:
        $a = "AutoOpen" nocase
        $b = "Document_Open" nocase
        $c = "Shell(" nocase
    condition:
        2 of them
}
