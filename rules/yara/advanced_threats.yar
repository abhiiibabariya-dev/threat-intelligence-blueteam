/*
    Advanced Threat Detection Rules - Blue Team Toolkit
    YARA rules for detecting advanced persistent threats and modern malware
*/

rule APT_Loader_Generic {
    meta:
        description = "Detects generic APT loader characteristics"
        author = "Blue Team Toolkit"
        severity = "critical"
        mitre = "T1055"
        date = "2024-01-15"

    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtCreateThreadEx" ascii
        $api5 = "RtlCreateUserThread" ascii
        $decrypt1 = { 8A ?? 34 ?? 88 ?? 4? }
        $decrypt2 = { 8A ?? 80 ?? ?? 88 ?? }

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($api*)) and
        (1 of ($decrypt*))
}

rule Backdoor_Reverse_Shell {
    meta:
        description = "Detects common reverse shell implementations"
        author = "Blue Team Toolkit"
        severity = "critical"
        mitre = "T1059"
        date = "2024-01-15"

    strings:
        $bash1 = "/bin/bash -i >& /dev/tcp/" ascii
        $bash2 = "bash -c 'bash -i >& /dev/tcp/" ascii
        $python1 = "socket.socket(socket.AF_INET" ascii
        $python2 = "subprocess.call(['/bin/sh','-i'])" ascii
        $python3 = "os.dup2(s.fileno()" ascii
        $perl1 = "socket(S,PF_INET,SOCK_STREAM" ascii
        $nc1 = "nc -e /bin/sh" ascii
        $nc2 = "ncat -e /bin/bash" ascii
        $php1 = "fsockopen(" ascii
        $php2 = "proc_open(" ascii
        $ruby1 = "TCPSocket.open" ascii
        $ps1 = "New-Object System.Net.Sockets.TCPClient" ascii
        $ps2 = "$stream = $client.GetStream()" ascii

    condition:
        any of them
}

rule Credential_Harvester {
    meta:
        description = "Detects credential harvesting tools and techniques"
        author = "Blue Team Toolkit"
        severity = "critical"
        mitre = "T1003"
        date = "2024-01-15"

    strings:
        $lsass1 = "sekurlsa::logonpasswords" ascii nocase
        $lsass2 = "sekurlsa::wdigest" ascii nocase
        $sam1 = "lsadump::sam" ascii nocase
        $sam2 = "lsadump::dcsync" ascii nocase
        $kerberos1 = "kerberos::list" ascii nocase
        $kerberos2 = "kerberos::golden" ascii nocase
        $lazagne1 = "LaZagne" ascii
        $procdump1 = "procdump" ascii nocase
        $comsvcs = "comsvcs.dll" ascii nocase
        $ntds1 = "ntds.dit" ascii nocase
        $pypykatz = "pypykatz" ascii

    condition:
        2 of them
}

rule Rootkit_Indicators {
    meta:
        description = "Detects rootkit behavior indicators"
        author = "Blue Team Toolkit"
        severity = "critical"
        mitre = "T1014"
        date = "2024-01-15"

    strings:
        $hook1 = "ZwQuerySystemInformation" ascii
        $hook2 = "ZwQueryDirectoryFile" ascii
        $hook3 = "NtEnumerateValueKey" ascii
        $hide1 = "HiddenProcess" ascii nocase
        $hide2 = "ProcessHide" ascii nocase
        $driver1 = "IoCreateDevice" ascii
        $driver2 = "ObRegisterCallbacks" ascii
        $syscall1 = { 0F 05 }  // syscall instruction
        $idt = "IDTR" ascii

    condition:
        uint16(0) == 0x5A4D and
        (3 of ($hook*, $hide*)) or
        (all of ($driver*) and 1 of ($hook*))
}

rule Cryptominer_Detection {
    meta:
        description = "Detects cryptocurrency mining software"
        author = "Blue Team Toolkit"
        severity = "high"
        mitre = "T1496"
        date = "2024-01-15"

    strings:
        $stratum1 = "stratum+tcp://" ascii
        $stratum2 = "stratum+ssl://" ascii
        $pool1 = "pool.minergate" ascii
        $pool2 = "xmrpool.eu" ascii
        $pool3 = "nanopool.org" ascii
        $pool4 = "2miners.com" ascii
        $pool5 = "supportxmr.com" ascii
        $algo1 = "cryptonight" ascii nocase
        $algo2 = "randomx" ascii nocase
        $algo3 = "ethash" ascii nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $xmr_wallet = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii

    condition:
        (1 of ($stratum*) and 1 of ($pool*)) or
        (1 of ($algo*) and (1 of ($pool*) or $wallet or $xmr_wallet))
}

rule InfoStealer_Generic {
    meta:
        description = "Detects generic information stealer behavior"
        author = "Blue Team Toolkit"
        severity = "high"
        mitre = "T1005"
        date = "2024-01-15"

    strings:
        $browser1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii nocase
        $browser2 = "\\Mozilla\\Firefox\\Profiles" ascii nocase
        $browser3 = "\\Microsoft\\Edge\\User Data" ascii nocase
        $browser4 = "logins.json" ascii
        $browser5 = "cookies.sqlite" ascii
        $crypto1 = "wallet.dat" ascii
        $crypto2 = "electrum" ascii nocase
        $crypto3 = "metamask" ascii nocase
        $ftp1 = "filezilla" ascii nocase
        $ftp2 = "recentservers.xml" ascii nocase
        $ssh1 = ".ssh/id_rsa" ascii
        $ssh2 = "putty\\sessions" ascii nocase
        $telegram = "\\Telegram Desktop\\tdata" ascii nocase
        $discord = "discord" ascii nocase

    condition:
        3 of them
}

rule Ransomware_Behavior {
    meta:
        description = "Detects ransomware behavioral patterns"
        author = "Blue Team Toolkit"
        severity = "critical"
        mitre = "T1486"
        date = "2024-01-15"

    strings:
        $shadow1 = "vssadmin delete shadows" ascii nocase
        $shadow2 = "wmic shadowcopy delete" ascii nocase
        $shadow3 = "bcdedit /set {default} recoveryenabled no" ascii nocase
        $shadow4 = "wbadmin delete catalog" ascii nocase
        $encrypt1 = "CryptEncrypt" ascii
        $encrypt2 = "CryptGenKey" ascii
        $encrypt3 = "CryptImportKey" ascii
        $ransom1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii nocase
        $ransom2 = "pay.*bitcoin" ascii nocase
        $ransom3 = "decrypt.*files" ascii nocase
        $ransom4 = ".onion" ascii
        $ext1 = ".encrypted" ascii
        $ext2 = ".locked" ascii
        $ext3 = ".crypted" ascii

    condition:
        (2 of ($shadow*)) or
        (1 of ($shadow*) and 2 of ($encrypt*)) or
        (2 of ($ransom*) and 1 of ($shadow*, $encrypt*, $ext*))
}
