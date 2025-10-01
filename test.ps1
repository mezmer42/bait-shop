function Get-Divisors {
    param([int]$val)
    $list = [System.Collections.Generic.List[int]]::new()
    for ($i = 1; $i -le [math]::Sqrt($val); $i++) {
        if ($val % $i -eq 0) {
            $list.Add($i)
            $other = $val / $i
            if ($other -ne $i) { $list.Add([int]$other) }
        }
    }
    return $list
}

function Get-Base64Encoded {
    param (
        [string]$Payload
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Payload)
    [Convert]::ToBase64String($bytes) 
}
<#
$encodedPayload = Get-Base64Encoded -Payload "Write-Output 'test'"
Write-Output $encodedPayload
$bytesPayload = [Convert]::FromBase64String($encodedPayload)
$stream = [System.IO.MemoryStream]::new()
$mode = [System.IO.Compression.CompressionMode]::Compress
$compressor = [System.IO.Compression.GzipStream]::new($stream,$mode)
$compressor.Write($bytesPayload, 0, $bytesPayload.Length)
$compressor.Dispose()
$compressed = $stream.ToArray()
$stream.Dispose()
Write-Output ([Convert]::ToBase64String($compressed))
$aes = [System.Security.Cryptography.AesManaged]::new()
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aes.GenerateKey()
$encryptor = $aes.CreateEncryptor()
$encrypted = $encryptor.TransformFinalBlock($compressed, 0, $compressed.Length)
$decryptor = $aes.CreateDecryptor()
$decrypted = $decryptor.TransformFinalBlock($encrypted, 0, $encrypted.Length)
Write-Output $([Convert]::ToBase64String($decrypted))
$inputStream = [System.IO.MemoryStream]::new($decrypted)
$mode2 = [System.IO.Compression.CompressionMode]::Decompress
$decompressor = [System.IO.Compression.GzipStream]::new($inputStream,$mode2)
$reader = [System.IO.MemoryStream]::new()
$decompressor.CopyTo($reader)
$decompressor.Dispose()
$inputStream.Dispose()
$payload = [System.Text.Encoding]::UTF8.GetString([byte[]]$reader.ToArray())
Write-Output ($payload)
#poweRsHell.exe -w normal  -noexit -enc $payload
#>

#pOwerSheLl.Exe -w 1 -nop -nol -enc $gkZhe;