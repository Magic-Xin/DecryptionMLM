using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DecryptionMLM
{
    internal static class Decryption
    {
        private static Encoding encoding = Encoding.UTF8;

        public static string DecryptDES(string decryptString, string key)
        {
            decryptString = decryptString.Replace('@', '/');
            byte[] bytes = ProcessDES(Convert.FromBase64String(decryptString), key, false);
            return encoding.GetString(bytes);
        }

        private static byte[] ProcessDES(byte[] data, string key, bool isEncrypt)
        {
            using (DESCryptoServiceProvider cryptoServiceProvider = new DESCryptoServiceProvider())
            {
                byte[] array1 = Md5(key);
                byte[] array2 = new ArraySegment<byte>(array1, 0, 8).ToArray<byte>();
                byte[] array3 = new ArraySegment<byte>(array1, 8, 8).ToArray<byte>();
                ICryptoTransform transform = isEncrypt ? cryptoServiceProvider.CreateEncryptor(array2, array3) : cryptoServiceProvider.CreateDecryptor(array2, array3);
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, transform, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }
        }

        public static byte[] Md5(string str)
        {
            using (MD5 md5 = MD5.Create())
                return md5.ComputeHash(Encoding.UTF8.GetBytes(str));
        }
        
        public static string De(string src)
        {
            if (src.StartsWith("mlm-"))
            {
                src = src.Remove(0, 4);
                src = DecryptDES(src, "mlm");
            }
            return src;
        }
        
        public static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Please enter encrypted file path");
                return;
            }
            string encryptedFilePath = args[0];
            string decryptedFilePath = encryptedFilePath + "-decrypted.xml";
            
            string encryptedXml = File.ReadAllText(encryptedFilePath);
            string decryptedXml = Regex.Replace(De(encryptedXml), @"\bMlmAction\b", "Action");

            File.WriteAllText(decryptedFilePath, decryptedXml);
            Console.WriteLine("Decrypted XML file saved: " + decryptedFilePath);
        }
    }
}