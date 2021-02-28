using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Globalization;

namespace App.Opayo
{
    public static class Crypt
    {
        public static string Encrypt(string input, string password)
        {
            return ByteArrayToHexString(AesEncrypt(Encoding.UTF8.GetBytes(input), password));
        }

        public static string Decrypt(string input, string password)
        {
            return Encoding.UTF8.GetString(AESdecrypt(ConvertHexStringToByteArray(input.Replace("@", "")), password));
        }

        private static byte[] ConvertHexStringToByteArray(string hexString)
        {
            if (hexString.Length % 2 != 0)
            {
                throw new ArgumentException("Binary key must have even number of digits");
            }

            byte[] data = new byte[hexString.Length / 2];

            for (int index = 0; index < data.Length; index++)
            {
                string byteValue = hexString.Substring(index * 2, 2);
                data[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            return data;
        }

        private static string ByteArrayToHexString(byte[] value)
        {
            return BitConverter.ToString(value).Replace("-", "");
        }

        private static byte[] AesEncrypt(byte[] input, string key)
        {
            using MemoryStream ms = new MemoryStream();
            var aes = GetAesManagedEncryption(key);
            CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(input, 0, input.Length);
            cs.FlushFinalBlock();
            return ms.ToArray();
        }

        private static byte[] AESdecrypt(byte[] input, string key)
        {
            using MemoryStream ms = new MemoryStream();
            var aes = GetAesManagedEncryption(key);
            CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(input, 0, input.Length);
            cs.FlushFinalBlock();
            return ms.ToArray();
        }

        private static AesManaged GetAesManagedEncryption(string key)
        {
            return new AesManaged
            {
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC,
                KeySize = 128,
                BlockSize = 128,
                Key = Encoding.UTF8.GetBytes(key),
                IV = Encoding.UTF8.GetBytes(key)
            };
        }
    }
}
