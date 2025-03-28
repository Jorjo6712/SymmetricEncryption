using System.Security.Cryptography;
using System.IO;

namespace SymmetricEncryption.EncryptionUtils
{
    public class DESUtils
    {
        public byte[] DESEncrypt(byte[] data, byte[] key, byte[] iv)
        {
            byte[] encrypted;
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                desAlg.Key = key;
                desAlg.IV = iv;

                ICryptoTransform encryptor = desAlg.CreateEncryptor(desAlg.Key, desAlg.IV);

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

        public byte[] DESDecrypt(byte[] data, byte[] key, byte[] iv)
        {
            byte[] decrypted;
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                desAlg.Key = key;
                desAlg.IV = iv;

                ICryptoTransform decryptor = desAlg.CreateDecryptor(desAlg.Key, desAlg.IV);

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