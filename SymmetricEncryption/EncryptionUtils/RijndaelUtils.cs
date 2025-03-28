using System.Security.Cryptography;
using System.IO;

namespace SymmetricEncryption.EncryptionUtils
{
    public class RijndaelUtils
    {
        public byte[] RijndaelEncrypt(byte[] data, byte[] key, byte[] iv)
        {
            byte[] encrypted;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = key;
                rijAlg.IV = iv;

                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(data, 0, data.Length);
                        csEncrypt.FlushFinalBlock();
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
            return encrypted;
        }

        public byte[] RijndaelDecrypt(byte[] data, byte[] key, byte[] iv)
        {
            byte[] decrypted;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = key;
                rijAlg.IV = iv;

                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(data))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (MemoryStream resultStream = new MemoryStream())
                        {
                            csDecrypt.CopyTo(resultStream);
                            decrypted = resultStream.ToArray();
                        }
                    }
                }
            }
            return decrypted;
        }
    }
}