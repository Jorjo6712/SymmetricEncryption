using System.Security.Cryptography;
using System.IO;

namespace SymmetricEncryption.EncryptionUtils
{
    public class RC2Utils
    {
        public byte[] RC2Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            byte[] encrypted;
            using (RC2CryptoServiceProvider rc2Alg = new RC2CryptoServiceProvider())
            {
                rc2Alg.Key = key;
                rc2Alg.IV = iv;

                ICryptoTransform encryptor = rc2Alg.CreateEncryptor(rc2Alg.Key, rc2Alg.IV);

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

        public byte[] RC2Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            byte[] decrypted;
            using (RC2CryptoServiceProvider rc2Alg = new RC2CryptoServiceProvider())
            {
                rc2Alg.Key = key;
                rc2Alg.IV = iv;

                ICryptoTransform decryptor = rc2Alg.CreateDecryptor(rc2Alg.Key, rc2Alg.IV);

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