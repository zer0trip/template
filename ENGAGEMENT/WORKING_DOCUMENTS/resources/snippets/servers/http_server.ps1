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
