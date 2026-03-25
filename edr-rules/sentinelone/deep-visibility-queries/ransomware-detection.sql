-- =============================================================================
-- SentinelOne Deep Visibility - Ransomware Detection Queries
-- MITRE ATT&CK: T1486, T1490
-- =============================================================================

-- Query 1: Shadow Copy Deletion (T1490)
SELECT EventTime, EndpointName, SrcProcUser, SrcProcName, SrcProcCmdLine
FROM events WHERE ObjectType = 'process' AND EventType = 'Process Creation'
AND (
    (SrcProcName = 'vssadmin.exe' AND SrcProcCmdLine CONTAINS 'delete shadows') OR
    (SrcProcName = 'wmic.exe' AND SrcProcCmdLine CONTAINS 'shadowcopy delete') OR
    (SrcProcName = 'bcdedit.exe' AND SrcProcCmdLine CONTAINS 'recoveryenabled') OR
    (SrcProcName = 'wbadmin.exe' AND SrcProcCmdLine CONTAINS 'delete catalog')
)

-- Query 2: Mass File Rename (Encryption Indicator)
SELECT EndpointName, SrcProcName, COUNT(*) AS FileCount,
    COUNT(DISTINCT FileExtension) AS UniqueExtensions
FROM events WHERE ObjectType = 'file' AND EventType = 'File Rename'
GROUP BY EndpointName, SrcProcName
HAVING FileCount > 100
ORDER BY FileCount DESC

-- Query 3: Ransom Note Detection
SELECT EventTime, EndpointName, SrcProcName, FilePath, FileName
FROM events WHERE ObjectType = 'file' AND EventType = 'File Creation'
AND (FileName CONTAINS 'readme' OR FileName CONTAINS 'decrypt' OR
     FileName CONTAINS 'restore' OR FileName CONTAINS 'recover' OR
     FileName CONTAINS 'ransom' OR FileName CONTAINS 'how_to')
AND (FileName LIKE '%.txt' OR FileName LIKE '%.html' OR FileName LIKE '%.hta')
