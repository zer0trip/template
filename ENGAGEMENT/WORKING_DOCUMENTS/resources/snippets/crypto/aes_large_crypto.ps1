Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Security.Cryptography;

    public static class Crypto
    {
        public static void Main(string[] args)
        {
            String usage = "Usage: powershell -file ./crypto.ps1 -opt encrypt|decrypt -file file -pass password";
            if(args.Length.Equals(3))
            {
                String option = args[0];
                String inputFile = args[1];
                String password = args[2];

                switch(option.ToLower())
                {
                    case "encrypt":
                        AES_Encrypt(inputFile, password);
                        break;
                    case "decrypt":
                        AES_Decrypt(inputFile, password);
                        break;
                    default:
                        Console.WriteLine(usage);
                        break;
                }
            } else
                Console.WriteLine(usage);
        }

        private static void AES_Encrypt(string inputFile, string password)
        {
            byte[] salt = GenerateRandomSalt();
            FileStream fsCrypt = new FileStream(inputFile + ".aes", FileMode.Create);
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;

            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Mode = CipherMode.CFB;

            fsCrypt.Write(salt, 0, salt.Length);
            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);
            FileStream fsIn = new FileStream(inputFile, FileMode.Open);
            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cs.Write(buffer, 0, read);
                }
                fsIn.Close();

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                cs.Close();
                fsCrypt.Close();
                File.Delete(inputFile);
            }
        }

        private static void AES_Decrypt(string inputFile, string password)
        {
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] salt = new byte[32];

            FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);

            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CFB;

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);
            FileStream fsOut = new FileStream(inputFile + ".decrypted", FileMode.Create);
            int read;
            byte[] buffer = new byte[1048576];

            try
            {
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    fsOut.Write(buffer, 0, read);
                }
            }
            catch (System.Security.Cryptography.CryptographicException ex_CryptographicException)
            {
                Console.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

            try
            {
                cs.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error by closing CryptoStream: " + ex.Message);
            }
            finally
            {
                fsOut.Close();
                fsCrypt.Close();

                File.Move(inputFile+".decrypted", inputFile.Remove(inputFile.Length - 4));
                File.Delete(inputFile);
            }
        }

        public static byte[] GenerateRandomSalt()
        {
            byte[] data = new byte[32];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                for (int i = 0; i < 10; i++)
                {
                    rng.GetBytes(data);
                }
            }
            return data;
        }
    }
"@

function Crypto
{
    param
    (
        [string] $Option = "encrypt",
        [string] $Destination = "",
        [string] $Passwd = ""
    )
    try {

        $Params = @($Option, $Destination, $Passwd)
        [Crypto]::Main($Params)

    } catch {
        Write-Output "Error: $($error[0])"
    }
}
