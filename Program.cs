using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Mime;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

[assembly: Guid("dfe757c4-3d37-4d84-b51a-83767489d14a")]

namespace IS4.YlandsApiProxy
{
    internal class Program
    {   
        const string proxyIp = "127.0.0.1";
        const string apiDomain = "ylands-api.bistudio.com";

        const string spoofVersion = "2.4.0";
        const string spoofBuild = "2.4.0|160441|ylands_rc2/Full/387";

        static CancellationTokenSource programCancellation = new();
        static readonly Assembly assembly = Assembly.GetAssembly(typeof(Program))!;
        static readonly Encoding hostsEncoding;
        static Program()
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            hostsEncoding = Encoding.GetEncoding(1252);
        }

        const ConsoleColor progressColor = ConsoleColor.White;
        const ConsoleColor notifyColor = ConsoleColor.Yellow;
        const ConsoleColor warnColor = ConsoleColor.Red;
        const ConsoleColor externalColor = ConsoleColor.Cyan;
        const ConsoleColor successColor = ConsoleColor.Green;

        static async Task Main(string[] args)
        {
            var defaultColor = Console.ForegroundColor;
            try
            {
                Console.CancelKeyPress += delegate
                {
                    Log(notifyColor, "Exiting program...");

                    // Cancel what is in progress, but not cleaup processes
                    Interlocked.Exchange(ref programCancellation, new()).Cancel();

                    // Wait for cleanup
                    Thread.Sleep(500);
                };

                Log(successColor, $"Ylands API proxy v{assembly.GetName().Version!.ToString(2)} by IS4 launched!");
                Log(notifyColor, "To report bugs, please visit https://github.com/IS4Code/Ylands-API-Proxy");

                if(ToggleProxy(false))
                {
                    await FlushDns();
                }

                if((await Dns.GetHostAddressesAsync(apiDomain, programCancellation.Token)).FirstOrDefault() is not { } realIp)
                {
                    Log(warnColor, $"Error: Could not retrieve the IP address of {apiDomain}!");
                    return;
                }

                var proxyIpObj = IPAddress.Parse(proxyIp);

                if(realIp.Equals(proxyIpObj))
                {
                    Log(warnColor, $"Error: Another proxy is running for {apiDomain}?");
                    return;
                }

                if(ToggleProxy(true))
                {
                    await FlushDns();
                }

                try
                {
                    var localAddresses = await Dns.GetHostAddressesAsync(apiDomain);
                    if(localAddresses.Length != 1 || !localAddresses[0].Equals(proxyIpObj))
                    {
                        Log(warnColor, $"Error: Modification to hosts did not take effect. The proxy could not be registered.");
                        return;
                    }

                    await RunProxyServer(realIp);
                }
                finally
                {
                    ToggleProxy(false);
                }
            }
            catch(Exception e) when(!Debugger.IsAttached)
            {
                if(e is not TaskCanceledException)
                {
                    Log(notifyColor, e.Message);
                }
            }
            finally
            {
                Log(successColor, "Server stopped!");
                Console.ForegroundColor = defaultColor;
            }
        }

        static readonly Regex ipOverrideLine = new(@"^\s*(?<ip>\d+\.\d+\.\d+\.\d+)\s+ylands-api\.bistudio\.com\s*(?:#|$)", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        static bool ToggleProxy(bool toggle)
        {
            Log(progressColor, $"{(toggle ? "Registering" : "Unregistering")} proxy for {apiDomain}...");

            var hosts = Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts");
            var bak = hosts + ".bak";

            File.Copy(hosts, bak, false);

            using var file = OpenFile(hosts);

            var lines = new List<string>();

            bool lineFound = false;

            using(var reader = new StreamReader(file, hostsEncoding, leaveOpen: true))
            {
                while(reader.ReadLine() is { } line)
                {
                    if(ipOverrideLine.Match(line) is not { Success: true } match)
                    {
                        // Unrelated line
                        lines.Add(line);
                        continue;
                    }

                    if(!match.Groups["ip"].ValueSpan.Equals(proxyIp, StringComparison.Ordinal))
                    {
                        // Conflicting line not produced by this program
                        lines.Add("#" + line);
                        continue;
                    }

                    lineFound = true;

                    if(toggle)
                    {
                        // Keep added
                        lines.Add(line);
                    }
                }
            }

            if(toggle == lineFound)
            {
                // No need to modify
                File.Delete(bak);
                return false;
            }

            if(toggle)
            {
                // Add proxy line
                lines.Add($"{proxyIp} ylands-api.bistudio.com # Ylands API proxy");
            }

            file.Position = 0;

            using(var writer = new StreamWriter(file, hostsEncoding, leaveOpen: true))
            {
                foreach(var line in lines)
                {
                    writer.WriteLine(line);
                }
            }

            file.SetLength(file.Position);

            // No exceptions, remove backup
            File.Delete(bak);

            return true;
        }

        static FileStream OpenFile(string path)
        {
            int attempts = 0;
            while(true)
            {
                try
                {
                    return new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                }
                catch(IOException) when(attempts++ < 5)
                {
                    Log(progressColor, "The file is locked, trying again...");

                    // Not async to block program finalization
                    Thread.Sleep(200);
                }
            }
        }

        static Task FlushDns()
        {
            return RunProcess("ipconfig", "/flushdns");
        }

        static async Task RunProxyServer(IPAddress realIp)
        {
            using var listener = new HttpListener
            {
                Prefixes = { $"https://{apiDomain}:443/ylands-api/" }
            };

            Log(progressColor, "Obtaining certificate...");
            var cert = GetCertificate();

            Log(progressColor, "Starting the server...");
            listener.Start();

            try
            {
                await InstallCertificate(cert);

                try
                {
                    Log(successColor, "Server started succesfully!");

                    using var client = new HttpClient();
                    client.BaseAddress = new UriBuilder(realIp.ToString())
                    {
                        Scheme = "https",
                        Port = 443
                    }.Uri;

                    while(await listener.GetContextAsync().WaitAsync(programCancellation.Token) is { } context)
                    {
                        ProxyRequest(context, client);
                    }
                }
                finally
                {
                    await UninstallCertificate();
                }
            }
            finally
            {
                Log(progressColor, "Stopping the server...");
                listener.Stop();
            }
        }

        static async void ProxyRequest(HttpListenerContext context, HttpClient client)
        {
            var request = context.Request;

            var builder = new UriBuilder(request.Url!);

            // Use the base from client
            builder.Scheme = null;
            builder.Host = null;

            Log(progressColor, $"{request.HttpMethod} {builder}");

            var query = HttpUtility.ParseQueryString(builder.Query);
            if(query["clientVersion"] is { } oldVersion)
            {
                // Version found in query
                Log(notifyColor, $"Upgrading URL version {oldVersion} to {spoofVersion}.");
                query["clientVersion"] = spoofVersion;
            }
            builder.Query = query.ToString();

            var message = new HttpRequestMessage(new HttpMethod(request.HttpMethod), builder.ToString());

            Stream inputStream;
            if(request.ContentType != null && new ContentType(request.ContentType).MediaType.Equals("application/json"))
            {
                var jsonNode = await JsonNode.ParseAsync(request.InputStream, cancellationToken: programCancellation.Token);
                
                if(jsonNode is JsonObject jsonObject && jsonObject.TryGetPropertyValue("clientVersion", out var versionProperty) && versionProperty?.GetValueKind() == JsonValueKind.String)
                {
                    // Version found in content
                    Log(notifyColor, $"Upgrading JSON version {versionProperty} to {spoofVersion}.");
                    jsonObject["clientVersion"] = JsonValue.Create(spoofVersion);

                    jsonObject["clientBuild"] = JsonValue.Create(spoofBuild);
                }

                inputStream = new MemoryStream();

                using(var writer = new Utf8JsonWriter(inputStream))
                {
                    jsonNode?.WriteTo(writer);
                }

                inputStream.Position = 0;
                message.Content = new StreamContent(inputStream);
            }
            else
            {
                inputStream = request.InputStream;
            }

            message.Headers.Clear();

            var headers = request.Headers;
            for(int i = 0; i < headers.Count; i++)
            {
                if(headers.GetKey(i) is { } key && headers.GetValues(i) is { Length: > 0 } values)
                {
                    if(key.StartsWith("Content-", StringComparison.OrdinalIgnoreCase))
                    {
                        (message.Content ??= new StreamContent(inputStream)).Headers.Add(key, values);
                    }
                    else
                    {
                        message.Headers.Add(key, values);
                    }
                }
            }

            if(inputStream is MemoryStream && message.Content is { Headers: { } contentHeaders })
            {
                // Content was modified
                contentHeaders.Remove("Content-Length");
                contentHeaders.Add("Content-Length", inputStream.Length.ToString());
            }

            message.Headers.Connection.Clear();
            message.Headers.ConnectionClose = true;

            using var newResponse = await client.SendAsync(message, programCancellation.Token);

            var response = context.Response;

            response.StatusCode = (int)newResponse.StatusCode;

            Log(progressColor, $"{response.StatusCode} {newResponse.StatusCode}");

            foreach(var header in newResponse.Headers)
            {
                foreach(var value in header.Value)
                {
                    response.AddHeader(header.Key, value);
                };
            }

            var content = newResponse.Content;
            foreach(var header in content.Headers)
            {
                foreach(var value in header.Value)
                {
                    response.AddHeader(header.Key, value);
                };
            }

            response.Headers.Remove("Content-Length");
            response.KeepAlive = false;
            response.SendChunked = true;

            using var outputStream = response.OutputStream;
            using var responseStream = await newResponse.Content.ReadAsStreamAsync(programCancellation.Token);
            await responseStream.CopyToAsync(outputStream, programCancellation.Token);
        }

        static X509Certificate2 GetCertificate()
        {
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            if(store.Certificates.FirstOrDefault(c => c.MatchesHostname(apiDomain, false) && DateTime.Now >= c.NotBefore && DateTime.Now <= c.NotAfter) is not { } cert)
            {
                // No certificate for domain installed
                Log(progressColor, $"Installing new certificate for {apiDomain}...");

                using var rsa = RSA.Create();
                var certRequest = new CertificateRequest("CN=" + apiDomain, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                cert = certRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddMonths(3));

                // Load as persisted
                cert = new(cert.Export(X509ContentType.Pkcs12, ""), "", X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

                if(!cert.HasPrivateKey)
                {
                    throw new ApplicationException("The certificate is missing the private key!");
                }

                store.Add(cert);
            }

            if(!cert.HasPrivateKey)
            {
                throw new ApplicationException("The certificate is missing the private key!");
            }

            return cert;
        }

        static async Task InstallCertificate(X509Certificate2 cert)
        {
            var guid = assembly.GetCustomAttribute<GuidAttribute>()!.Value;

            int attempts = 0;
            while(true)
            {
                try
                {
                    Log(progressColor, "Registering certificate...");
                    await RunProcess("netsh", "http", "add", "sslcert", "ipport=0.0.0.0:443", $"certhash={cert.Thumbprint}", $"appid={{{guid:D}}}");
                    return;
                }
                catch when(attempts++ < 3)
                {
                    Log(notifyColor, "Cannot install certificate, maybe it is already installed.");
                    await UninstallCertificate();
                }
            }
        }

        static async Task UninstallCertificate()
        {
            Log(progressColor, "Unregistering certificate...");
            try
            {
                await RunProcess("netsh", "http", "delete", "sslcert", "ipport=0.0.0.0:443");
            }
            catch
            {

            }
        }

        static async Task RunProcess(string name, params string[] args)
        {
            Console.ForegroundColor = externalColor;
            var proc = Process.Start(new ProcessStartInfo(name, args)
            {
                UseShellExecute = false,
                CreateNoWindow = false
            });

            if(proc == null)
            {
                throw new ApplicationException($"Process '{name}' could not be started.");
            }

            await proc.WaitForExitAsync(programCancellation.Token);

            var exitCode = proc.ExitCode;

            if(exitCode != 0)
            {
                throw new ApplicationException($"Process '{name}' failed with code {exitCode}");
            }
        }

        static void Log(ConsoleColor color, string text)
        {
            Console.ForegroundColor = color;
            Console.Error.WriteLine(text);
        }
    }
}
