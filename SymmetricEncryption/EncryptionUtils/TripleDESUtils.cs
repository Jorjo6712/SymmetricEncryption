using System.Security.Cryptography;
using System.IO;

namespace SymmetricEncryption.EncryptionUtils
{
    public class TripleDESUtils
    {
        public byte[] TripleDESEncrypt(byte[] data, byte[] key, byte[] iv)
        {
            byte[] encrypted;
            using (TripleDESCryptoServiceProvider tdesAlg = new TripleDESCryptoServiceProvider())
            {
                tdesAlg.Key = key;
                tdesAlg.IV = iv;

                ICryptoTransform encryptor = tdesAlg.CreateEncryptor(tdesAlg.Key, tdesAlg.IV);

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

        public byte[] TripleDESDecrypt(byte[] data, byte[] key, byte[] iv)
        {
            byte[] decrypted;
            using (TripleDESCryptoServiceProvider tdesAlg = new TripleDESCryptoServiceProvider())
            {
                tdesAlg.Key = key;
                tdesAlg.IV = iv;

                ICryptoTransform decryptor = tdesAlg.CreateDecryptor(tdesAlg.Key, tdesAlg.IV);

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