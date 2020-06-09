using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

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
            throw new Exception("SmallCrypto - rsaEncrypt");
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
            throw new Exception("SmallCrypto - rsaDecrypt");
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
            throw new Exception("SmallCrypto - encrypt");
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
            throw new Exception("SmallCrypto - decrypt");
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
