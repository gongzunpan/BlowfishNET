/* 
  Copyright 2001-2007 Markus Hahn 
  All rights reserved. See documentation for license details.  
*/

using System;
using System.Text;
using System.Security.Cryptography;

namespace BlowfishNET
{

    /// <summary>An easy-to-use-string encryption solution using Blowfish/CBC.</summary>
    /// <remarks>As a simple solution for developers, who want nothing more than protect
    /// single strings with a password, this class provides the necessary functionality.
    /// The password (aka as key) is hashed using the SHA-1 implementation of the .NET
    /// framework. The random number generator for the CBC initialization vector (IV)
    /// and BASE64 are used from the framework's security services.</remarks>
    public class BlowfishSimple
    {
        BlowfishCBC bfc;
        RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        String keyChecksum;

        /// <summary>The secure checksum of the key used for encryption.</summary>
        /// <remarks>Store this checksum somewhere to be able to check later on by
        /// calling the VerifyKey() method, to see if a key matches for decryption
        /// or not.</remarks> 
        public String KeyChecksum
        {
            get
            {
                return this.keyChecksum;
            } 
        }

        static byte[] TransformKey(String key)
        {
            UTF8Encoding ue = new UTF8Encoding();
            return ue.GetBytes(key);
        }

        static byte[] CalcKeyChecksum(byte[] salt, byte[] key)
        {
            HashAlgorithm sha = new SHA1CryptoServiceProvider();

            byte[] keyCombo = new byte[20 + key.Length];

            Array.Copy(salt, 0, keyCombo, 0, 20);
            Array.Copy(key, 0, keyCombo, 20, key.Length);

            byte[] result = sha.ComputeHash(keyCombo);

            Array.Clear(keyCombo, 0, keyCombo.Length);

            return result;
        }

        /// <summary>To verify a key before it is used for decryption.</summary>
        /// <remarks> By passing the currently available key and a key checksum
        /// retrieved during the former encryption process you will be assured that
        /// the key will decrypt the data correctly.</remarks> 
        /// <param name="key">The key to verify.</param> 
        /// <param name="keyChecksum">The original key checksum.</param> 
        /// <returns>True if key seems to be the right one or false if it doesn't match.
        /// </returns> 
        public static bool VerifyKey(String key, String keyChecksum)
        {
            byte[] checksumCombo = Convert.FromBase64String(keyChecksum);
 
            if (40 != checksumCombo.Length) 
            {       
                return false;
            }

            byte[] keyRaw = TransformKey(key);
            byte[] checksum = CalcKeyChecksum(checksumCombo, keyRaw);
 
            int i = 0;
            while (i < checksum.Length)
            {
                if (checksum[i] != checksumCombo[checksum.Length + i]) 
                {   
                    break;
                }
                i++;
            } 
   
            return (i == checksum.Length);
        }

        /// <summary>Empty constructor. Before using the instance you MUST call Initialize(),
        /// otherwise any result or behavior is unpredictable!</summary>
        public BlowfishSimple()
        {
        }

        /// <summary>Default constructor.</summary>
        /// <param name="keyStr">The string which is used as the key material (aka as
        /// password or passphrase). Internally the UTF-8 representation of this string
        /// is used, hashed with SHA-1. The result is then a 160bit binary key. Notice
        /// that this transformation will not make weak (meaning short or easily guessable)
        /// keys any safer!</param>
        public BlowfishSimple(String keyStr)
        {
            Initialize(keyStr);
        }

        /// <summary>Initializes the instance with a (new) key string.</summary>
        /// <param name="keyStr">The key material.</param>
        /// <see cref="BlowfishSimple(String)"/>
        public void Initialize(String keyStr)
        {
            byte[] keyRaw = TransformKey(keyStr);

            HashAlgorithm sha = new SHA1CryptoServiceProvider();
            byte[] key = sha.ComputeHash(keyRaw);

            byte[] checksumSalt = new byte[20];
            this.rng.GetBytes(checksumSalt);

            byte[] checksum = CalcKeyChecksum(checksumSalt, keyRaw);

            byte[] checksumCombo = new byte[checksumSalt.Length + checksum.Length];

            Array.Copy(
                checksumSalt,
                0,
                checksumCombo,
                0,
                checksumSalt.Length);

            Array.Copy(
                checksum,
                0,
                checksumCombo,
                checksumSalt.Length,
                checksum.Length);

            this.keyChecksum = Convert.ToBase64String(checksumCombo);

            this.bfc = new BlowfishCBC(key, 0, key.Length);

            Array.Clear(keyRaw, 0, keyRaw.Length);
            Array.Clear(key, 0, key.Length);
        }

        /// <summary>Encrypts a string.</summary>
        /// <remarks>For efficiency the given string will be UTF-8 encoded and padded to
        /// the next 8byte block border. The CBC IV plus the encrypted data will then be
        /// BASE64 encoded and  returned as the final encryption result.</remarks>
        /// <param name="plainText">The string to encrypt.</param> 
        /// <returns>The encrypted string.</returns> 
        public String Encrypt(String plainText)
        {
            byte[] ueData = Encoding.UTF8.GetBytes(plainText);

            int origLen = ueData.Length;
            int len = origLen;

            int mod = len % BlowfishCBC.BLOCK_SIZE;
            len = (len - mod) + BlowfishCBC.BLOCK_SIZE;

            byte[] inBuf = new byte[len];

            Array.Copy(ueData, 0, inBuf, 0, origLen);

            int i = len - (BlowfishCBC.BLOCK_SIZE - mod);
            
            while (i < len) 
            {   
                inBuf[i++] = (byte)mod;
            }

            byte[] outBuf = new byte[inBuf.Length + BlowfishCBC.BLOCK_SIZE];

            byte[] iv = new byte[BlowfishCBC.BLOCK_SIZE];
            this.rng.GetBytes(iv);
            this.bfc.IV = iv;

            this.bfc.Encrypt(
                inBuf, 
                0, 
                outBuf, 
                BlowfishCBC.BLOCK_SIZE, 
                inBuf.Length);

            Array.Copy(iv, 0, outBuf, 0, BlowfishCBC.BLOCK_SIZE);  

            String sResult = Convert.ToBase64String(outBuf);
 
            Array.Clear(inBuf, 0, inBuf.Length);

            return sResult;
        }

        /// <summary>Decrypts a string which was formely generated by the Encrypt()
        /// method and a particular key.</summary>        
        /// <remarks>The string has to be decrypted with the same key, otherwise the
        /// result will be simply garbage. If you want to check if the key is the right
        /// one use the VerifyKey() method.</remarks>
        /// <param name="cipherText">The string to decrypt.</param> 
        /// <returns>The decrypted string, or null on error (usually caused by a wrong
        /// key passed in).</returns> 
        public String Decrypt(String cipherText)
        {
            byte[] cdata;

            try
            {
                cdata = Convert.FromBase64String(cipherText);
            }
            catch (FormatException)
            {
                return null;
            }   

            if (BlowfishCBC.BLOCK_SIZE > cdata.Length) 
            {   
                return null;
            }

            this.bfc.SetIV(cdata, 0);

            byte[] outBuf = new byte[cdata.Length];

            int dataAbs = cdata.Length - BlowfishCBC.BLOCK_SIZE; 
            
            dataAbs /= BlowfishCBC.BLOCK_SIZE;  
            dataAbs *= BlowfishCBC.BLOCK_SIZE;  

            this.bfc.Decrypt(
                cdata, 
                BlowfishCBC.BLOCK_SIZE, 
                outBuf, 
                0, 
                dataAbs);

            int mod = outBuf[dataAbs - 1];

            if ((0 > mod) || (BlowfishCBC.BLOCK_SIZE <= mod))
            {
                return null;
            }

            int origSize = dataAbs 
                - BlowfishCBC.BLOCK_SIZE 
                + outBuf[dataAbs - 1];
 
            return Encoding.UTF8.GetString(outBuf, 0, origSize);
        }
    }
}
