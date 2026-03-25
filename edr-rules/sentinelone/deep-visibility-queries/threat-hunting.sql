-- =============================================================================
-- SentinelOne Deep Visibility - Threat Hunting Queries
-- MITRE ATT&CK: Multiple techniques
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Query 1: Suspicious PowerShell Execution (T1059.001)
-- ---------------------------------------------------------------------------
SELECT
    EventTime, EndpointName, SrcProcUser,
    SrcProcName, SrcProcCmdLine, SrcProcParentName
FROM events
WHERE SrcProcName = 'powershell.exe' OR SrcProcName = 'pwsh.exe'
AND (
    SrcProcCmdLine CONTAINS '-enc' OR
    SrcProcCmdLine CONTAINS 'FromBase64' OR
    SrcProcCmdLine CONTAINS 'DownloadString' OR
    SrcProcCmdLine CONTAINS 'Invoke-Expression' OR
    SrcProcCmdLine CONTAINS 'IEX' OR
    SrcProcCmdLine CONTAINS 'bypass' OR
    SrcProcCmdLine CONTAINS 'AmsiUtils' OR
    SrcProcCmdLine CONTAINS 'WebClient'
)
ORDER BY EventTime DESC

-- ---------------------------------------------------------------------------
-- Query 2: LOLBin Abuse Detection (T1218)
-- ---------------------------------------------------------------------------
SELECT
    EventTime, EndpointName, SrcProcUser,
    SrcProcName, SrcProcCmdLine, SrcProcParentName
FROM events
WHERE SrcProcName IN ('mshta.exe', 'certutil.exe', 'regsvr32.exe', 'rundll32.exe',
    'msbuild.exe', 'cmstp.exe', 'installutil.exe')
AND (
    SrcProcCmdLine CONTAINS 'http' OR
    SrcProcCmdLine CONTAINS 'javascript' OR
    SrcProcCmdLine CONTAINS 'vbscript' OR
    SrcProcCmdLine CONTAINS '-decode' OR
    SrcProcCmdLine CONTAINS '-urlcache' OR
    SrcProcCmdLine CONTAINS 'scrobj.dll'
)
ORDER BY EventTime DESC

-- ---------------------------------------------------------------------------
-- Query 3: Credential Dumping Detection (T1003)
-- ---------------------------------------------------------------------------
SELECT
    EventTime, EndpointName, SrcProcUser,
    SrcProcName, SrcProcCmdLine, TgtProcName
FROM events
WHERE
    SrcProcCmdLine CONTAINS 'mimikatz' OR
    SrcProcCmdLine CONTAINS 'sekurlsa' OR
    SrcProcCmdLine CONTAINS 'lsadump' OR
    (SrcProcName = 'procdump.exe' AND SrcProcCmdLine CONTAINS 'lsass') OR
    (SrcProcName = 'rundll32.exe' AND SrcProcCmdLine CONTAINS 'comsvcs' AND SrcProcCmdLine CONTAINS 'MiniDump')
ORDER BY EventTime DESC

-- ---------------------------------------------------------------------------
-- Query 4: Lateral Movement via SMB (T1021.002)
-- ---------------------------------------------------------------------------
SELECT
    EventTime, EndpointName, SrcProcUser,
    NetConnOutCount, NetConnInCount,
    DstIP, DstPort, SrcProcName
FROM events
WHERE DstPort = 445
AND NetConnOutCount > 0
AND ObjectType = 'ip'
ORDER BY EventTime DESC

-- ---------------------------------------------------------------------------
-- Query 5: Persistence via Registry (T1547.001)
-- ---------------------------------------------------------------------------
SELECT
    EventTime, EndpointName, SrcProcUser,
    SrcProcName, RegistryKeyPath, RegistryValue
FROM events
WHERE ObjectType = 'registry'
AND EventType = 'Registry Value Modified'
AND (
    RegistryKeyPath CONTAINS '\\Run\\' OR
    RegistryKeyPath CONTAINS '\\RunOnce\\' OR
    RegistryKeyPath CONTAINS '\\Winlogon\\Shell' OR
    RegistryKeyPath CONTAINS '\\Winlogon\\Userinit'
)
AND SrcProcName NOT IN ('explorer.exe', 'msiexec.exe')
ORDER BY EventTime DESC

-- ---------------------------------------------------------------------------
-- Query 6: Process Execution from Temp/Downloads (T1036)
-- ---------------------------------------------------------------------------
SELECT
    EventTime, EndpointName, SrcProcUser,
    SrcProcName, SrcProcImagePath, SrcProcCmdLine,
    SrcProcParentName, FileSHA256
FROM events
WHERE ObjectType = 'process'
AND EventType = 'Process Creation'
AND (
    SrcProcImagePath CONTAINS '\\Temp\\' OR
    SrcProcImagePath CONTAINS '\\Downloads\\' OR
    SrcProcImagePath CONTAINS '\\AppData\\Local\\Temp\\' OR
    SrcProcImagePath CONTAINS '\\Public\\'
)
AND SrcProcName LIKE '%.exe'
ORDER BY EventTime DESC

-- ---------------------------------------------------------------------------
-- Query 7: Suspicious Parent-Child Process Relationship (T1059)
-- ---------------------------------------------------------------------------
SELECT
    EventTime, EndpointName,
    SrcProcParentName AS ParentProcess,
    SrcProcName AS ChildProcess,
    SrcProcCmdLine AS ChildCommandLine
FROM events
WHERE ObjectType = 'process'
AND EventType = 'Process Creation'
AND SrcProcParentName IN ('winword.exe', 'excel.exe', 'outlook.exe', 'powerpnt.exe')
AND SrcProcName IN ('cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe')
ORDER BY EventTime DESC

-- ---------------------------------------------------------------------------
-- Query 8: DNS Query to Newly Registered Domain (T1568)
-- ---------------------------------------------------------------------------
SELECT
    EventTime, EndpointName, SrcProcName,
    DnsRequest, DnsResponse
FROM events
WHERE ObjectType = 'dns'
AND EventType = 'DNS Query'
AND DnsRequest NOT CONTAINS '.microsoft.com'
AND DnsRequest NOT CONTAINS '.google.com'
AND DnsRequest NOT CONTAINS '.amazonaws.com'
AND LENGTH(DnsRequest) > 40
ORDER BY EventTime DESC
