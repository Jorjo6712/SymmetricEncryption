using System.Security.Cryptography;

namespace SymmetricEncryption.EncryptionUtils
{
    public class AESUtils
    {
        public byte[] AESEncrypt(byte[] data, byte[] key, byte[] iv)
        {
            byte[] encrypted;
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(data);
                        }
                    }

                    encrypted = msEncrypt.ToArray();
                }
            }

            return encrypted;
        }

        public byte[] AESDecrypt(byte[] data, byte[] key, byte[] iv)
        {
            byte[] decrypted;
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(data))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            decrypted = System.Text.Encoding.UTF8.GetBytes(srDecrypt.ReadToEnd());
                        }
                    }
                }
            }

            return decrypted;
        }
    }
}