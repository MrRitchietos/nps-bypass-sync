# Minimal RADIUS client for tests: sends a PAP Access-Request (with Message-Authenticator)
# and returns the reply code (2 = Accept, 3 = Reject) or $null on timeout.

function New-RandomBytes ([int]$Count)
{
    $b = New-Object byte[] $Count
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return , $b
}

function New-Attribute ([byte]$Type, [byte[]]$Value)
{
    $a = New-Object byte[] ($Value.Length + 2)
    $a[0] = $Type
    $a[1] = [byte]($Value.Length + 2)
    [Array]::Copy($Value, 0, $a, 2, $Value.Length)
    return , $a
}

function Send-RadiusPap
{
    param
    (
        [Parameter(Mandatory)][string]$UserName,
        [string]$Password = 'x',
        [string]$Secret = 'TestSecret123',
        [string]$Server = '127.0.0.1',
        [int]$Port = 1812,
        [int]$TimeoutMs = 4000
    )
    $enc = [Text.Encoding]::UTF8
    $secretBytes = $enc.GetBytes($Secret)
    $auth = New-RandomBytes 16
    $md5 = [Security.Cryptography.MD5]::Create()

    # User-Password (RFC 2865 5.2)
    $pw = $enc.GetBytes($Password)
    $len = [Math]::Max(16, [int][Math]::Ceiling($pw.Length / 16) * 16)
    $padded = New-Object byte[] $len
    [Array]::Copy($pw, $padded, $pw.Length)
    $hidden = New-Object byte[] $len
    $prev = $auth
    for ($i = 0; $i -lt $len; $i += 16)
    {
        $b = $md5.ComputeHash([byte[]]($secretBytes + $prev))
        for ($j = 0; $j -lt 16; $j++) { $hidden[$i + $j] = $padded[$i + $j] -bxor $b[$j] }
        $prev = $hidden[$i..($i + 15)]
    }

    $attrs = New-Object Collections.Generic.List[byte]
    $attrs.AddRange([byte[]](New-Attribute 1 $enc.GetBytes($UserName)))
    $attrs.AddRange([byte[]](New-Attribute 2 $hidden))
    $attrs.AddRange([byte[]](New-Attribute 4 ([byte[]](127, 0, 0, 1))))
    $attrs.AddRange([byte[]](New-Attribute 61 ([byte[]](0, 0, 0, 5))))   # NAS-Port-Type Virtual
    $maOffset = 20 + $attrs.Count + 2
    $attrs.AddRange([byte[]](New-Attribute 80 (New-Object byte[] 16)))

    $total = 20 + $attrs.Count
    $packet = New-Object byte[] $total
    $packet[0] = 1
    $packet[1] = [byte](Get-Random -Minimum 0 -Maximum 255)
    $packet[2] = [byte]($total -shr 8)
    $packet[3] = [byte]($total -band 0xFF)
    [Array]::Copy($auth, 0, $packet, 4, 16)
    $attrs.CopyTo($packet, 20)
    $hmac = New-Object Security.Cryptography.HMACMD5 (, $secretBytes)
    $ma = $hmac.ComputeHash($packet)
    [Array]::Copy($ma, 0, $packet, $maOffset, 16)

    $udp = New-Object Net.Sockets.UdpClient
    try
    {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        [void]$udp.Send($packet, $packet.Length, $Server, $Port)
        $ep = New-Object Net.IPEndPoint ([Net.IPAddress]::Any, 0)
        try { $reply = $udp.Receive([ref]$ep) } catch { return $null }
        return [int]$reply[0]
    }
    finally { $udp.Close() }
}

Export-ModuleMember -Function Send-RadiusPap
