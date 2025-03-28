using System;
using System.Diagnostics;
using System.Text;
using SymmetricEncryption.EncryptionUtils;

namespace SymmetricEncryption
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Welcome to Symmetric Encryption!");
            Console.WriteLine("Choose your encryption algorithm and method:");
            Console.WriteLine("1) AES encryption");
            Console.WriteLine("2) AES decryption");
            Console.WriteLine("3) TripleDES encryption");
            Console.WriteLine("4) TripleDES decryption");
            Console.WriteLine("5) DES encryption");
            Console.WriteLine("6) DES decryption");
            Console.WriteLine("7) RC2 encryption");
            Console.WriteLine("8) RC2 decryption");
            Console.WriteLine("9) Rijndael encryption");
            Console.WriteLine("10) Rijndael decryption");
            string input = Console.ReadLine();

            switch (input)
            {
                case "1":
                    PerformAESEncryption();
                    break;
                case "2":
                    PerformAESDecryption();
                    break;
                case "3":
                    PerformTripleDESEncryption();
                    break;
                case "4":
                    PerformTripleDESDecryption();
                    break;
                case "5":
                    PerformDESEncryption();
                    break;
                case "6":
                    PerformDESDecryption();
                    break;
                case "7":
                    PerformRC2Encryption();
                    break;
                case "8":
                    PerformRC2Decryption();
                    break;
                case "9":
                    PerformRijndaelEncryption();
                    break;
                case "10":
                    PerformRijndaelDecryption();
                    break;
                default:
                    Console.WriteLine("Invalid option selected.");
                    break;
            }
        }

        private static void PerformAESEncryption()
        {
            Console.WriteLine("AES encryption");
            byte[] dataToEncrypt = GetDataToEncrypt();
            byte[] key = GetKey();
            byte[] iv = GetIV();

            AESUtils aesUtils = new AESUtils();
            Stopwatch stopwatch = Stopwatch.StartNew();
            byte[] encrypted = aesUtils.AESEncrypt(dataToEncrypt, key, iv);
            stopwatch.Stop();
            Console.WriteLine("Encrypted text: " + Convert.ToBase64String(encrypted));
            Console.WriteLine("Time taken to encrypt: " + stopwatch.ElapsedMilliseconds + " ms");
        }

        private static void PerformAESDecryption()
        {
            Console.WriteLine("AES decryption");
            byte[] dataToDecrypt = GetDataToDecrypt();
            byte[] key = GetKey();
            byte[] iv = GetIV();

            AESUtils aesUtils = new AESUtils();
            Stopwatch stopwatch = Stopwatch.StartNew();
            byte[] decrypted = aesUtils.AESDecrypt(dataToDecrypt, key, iv);
            stopwatch.Stop();
            Console.WriteLine("Decrypted text: " + Encoding.UTF8.GetString(decrypted));
            Console.WriteLine("Time taken to decrypt: " + stopwatch.ElapsedMilliseconds + " ms");
        }

        private static void PerformTripleDESEncryption()
        {
            Console.WriteLine("TripleDES encryption");
            byte[] dataToEncrypt = GetDataToEncrypt();
            byte[] key = GetKey();
            byte[] iv = GetIV();

            TripleDESUtils tripleDESUtils = new TripleDESUtils();
            Stopwatch stopwatch = Stopwatch.StartNew();
            byte[] encrypted = tripleDESUtils.TripleDESEncrypt(dataToEncrypt, key, iv);
            stopwatch.Stop();
            Console.WriteLine("Encrypted text: " + Convert.ToBase64String(encrypted));
            Console.WriteLine("Time taken to encrypt: " + stopwatch.ElapsedMilliseconds + " ms");
        }

        private static void PerformTripleDESDecryption()
        {
            Console.WriteLine("TripleDES decryption");
            byte[] dataToDecrypt = GetDataToDecrypt();
            byte[] key = GetKey();
            byte[] iv = GetIV();

            TripleDESUtils tripleDESUtils = new TripleDESUtils();
            Stopwatch stopwatch = Stopwatch.StartNew();
            byte[] decrypted = tripleDESUtils.TripleDESDecrypt(dataToDecrypt, key, iv);
            stopwatch.Stop();
            Console.WriteLine("Decrypted text: " + Encoding.UTF8.GetString(decrypted));
            Console.WriteLine("Time taken to decrypt: " + stopwatch.ElapsedMilliseconds + " ms");
        }

        private static void PerformDESEncryption()
        {
            Console.WriteLine("DES encryption");
            byte[] dataToEncrypt = GetDataToEncrypt();
            byte[] key = GetKey();
            byte[] iv = GetIV();

            DESUtils desUtils = new DESUtils();
            Stopwatch stopwatch = Stopwatch.StartNew();
            byte[] encrypted = desUtils.DESEncrypt(dataToEncrypt, key, iv);
            stopwatch.Stop();
            Console.WriteLine("Encrypted text: " + Convert.ToBase64String(encrypted));
            Console.WriteLine("Time taken to encrypt: " + stopwatch.ElapsedMilliseconds + " ms");
        }

        private static void PerformDESDecryption()
        {
            Console.WriteLine("DES decryption");
            byte[] dataToDecrypt = GetDataToDecrypt();
            byte[] key = GetKey();
            byte[] iv = GetIV();

            DESUtils desUtils = new DESUtils();
            Stopwatch stopwatch = Stopwatch.StartNew();
            byte[] decrypted = desUtils.DESDecrypt(dataToDecrypt, key, iv);
            stopwatch.Stop();
            Console.WriteLine("Decrypted text: " + Encoding.UTF8.GetString(decrypted));
            Console.WriteLine("Time taken to decrypt: " + stopwatch.ElapsedMilliseconds + " ms");
        }

        private static void PerformRC2Encryption()
        {
            Console.WriteLine("RC2 encryption");
            byte[] dataToEncrypt = GetDataToEncrypt();
            byte[] key = GetKey();
            byte[] iv = GetIV();

            RC2Utils rc2Utils = new RC2Utils();
            Stopwatch stopwatch = Stopwatch.StartNew();
            byte[] encrypted = rc2Utils.RC2Encrypt(dataToEncrypt, key, iv);
            stopwatch.Stop();
            Console.WriteLine("Encrypted text: " + Convert.ToBase64String(encrypted));
            Console.WriteLine("Time taken to encrypt: " + stopwatch.ElapsedMilliseconds + " ms");
        }

        private static void PerformRC2Decryption()
        {
            Console.WriteLine("RC2 decryption");
            byte[] dataToDecrypt = GetDataToDecrypt();
            byte[] key = GetKey();
            byte[] iv = GetIV();

            RC2Utils rc2Utils = new RC2Utils();
            Stopwatch stopwatch = Stopwatch.StartNew();
            byte[] decrypted = rc2Utils.RC2Decrypt(dataToDecrypt, key, iv);
            stopwatch.Stop();
            Console.WriteLine("Decrypted text: " + Encoding.UTF8.GetString(decrypted));
            Console.WriteLine("Time taken to decrypt: " + stopwatch.ElapsedMilliseconds + " ms");
        }

        private static void PerformRijndaelEncryption()
        {
            Console.WriteLine("Rijndael encryption");
            byte[] dataToEncrypt = GetDataToEncrypt();
            byte[] key = GetKey();
            byte[] iv = GetIV();

            RijndaelUtils rijndaelUtils = new RijndaelUtils();
            Stopwatch stopwatch = Stopwatch.StartNew();
            byte[] encrypted = rijndaelUtils.RijndaelEncrypt(dataToEncrypt, key, iv);
            stopwatch.Stop();
            Console.WriteLine("Encrypted text: " + Convert.ToBase64String(encrypted));
            Console.WriteLine("Time taken to encrypt: " + stopwatch.ElapsedMilliseconds + " ms");
        }

        private static void PerformRijndaelDecryption()
        {
            Console.WriteLine("Rijndael decryption");
            byte[] dataToDecrypt = GetDataToDecrypt();
            byte[] key = GetKey();
            byte[] iv = GetIV();

            RijndaelUtils rijndaelUtils = new RijndaelUtils();
            Stopwatch stopwatch = Stopwatch.StartNew();
            byte[] decrypted = rijndaelUtils.RijndaelDecrypt(dataToDecrypt, key, iv);
            stopwatch.Stop();
            Console.WriteLine("Decrypted text: " + Encoding.UTF8.GetString(decrypted));
            Console.WriteLine("Time taken to decrypt: " + stopwatch.ElapsedMilliseconds + " ms");
        }

        private static byte[] GetDataToEncrypt()
        {
            Console.WriteLine("Enter the text to encrypt (ASCII or HEX):");
            string textToEncrypt = Console.ReadLine();
            Console.WriteLine("Is the input text in HEX format? (yes/no):");
            string isHex = Console.ReadLine().ToLower();

            if (isHex == "yes")
            {
                return Convert.FromHexString(textToEncrypt);
            }
            else
            {
                return Encoding.UTF8.GetBytes(textToEncrypt);
            }
        }

        private static byte[] GetDataToDecrypt()
        {
            Console.WriteLine("Enter the text to decrypt (Base64):");
            string textToDecrypt = Console.ReadLine();
            return Convert.FromBase64String(textToDecrypt);
        }

        private static byte[] GetKey()
        {
            Console.WriteLine("Enter the key (HEX):");
            return Convert.FromHexString(Console.ReadLine());
        }

        private static byte[] GetIV()
        {
            Console.WriteLine("Enter the IV (HEX):");
            return Convert.FromHexString(Console.ReadLine());
        }
    }
}