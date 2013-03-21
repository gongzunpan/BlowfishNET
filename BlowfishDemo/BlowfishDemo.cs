/* 
  Copyright 2001-2007 Markus Hahn 
  All rights reserved. See documentation for license details.  
*/

using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using BlowfishNET;
using BlowfishNET.JavaInterop;
using BlowfishNET.Demo.Properties;

namespace BlowfishNET.Demo
{
    /// <summary>Command line Blowfish.NET demonstration.</summary>
    class Demo1
    {
        // We use on central random number generator for all the examples. In the
        // real word we would rather use a secure random number random generator,
        // e.g. the one in System.Security.Cryptography.RNGCryptoServiceProvider.
        static RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        #region Show Basics

        static void ShowBlowfishECB()
        {
            int i;
            byte[] key, plain;
            byte[] encrypted;
            byte[] decrypted;
            BlowfishECB bfe;


            // Run the self test to make sure the implementation is fine.
            if (!BlowfishECB.RunSelfTest())
            {
                System.Console.WriteLine(Resources.BFDEMO_SELFTEST_FAILED);
                return;
            }
            else
            {
                System.Console.WriteLine(Resources.BFDEMO_SELFTEST_PASSED);
            }
        
            // Encrypt and decrypt an array of bytes. Motice that we create an
            // aligned array for this, so we don't have to take care about
            // padding here.
            plain = new byte[BlowfishECB.BLOCK_SIZE * 100];

            encrypted = new byte[plain.Length];
            decrypted = new byte[plain.Length];
            
            // They key gets generated out of random data, which is a common
            // practice in the real world for dynamic purposes. Other methods are
            // e.g. to hash down a password using SHA.
            key = new byte[BlowfishECB.MAX_KEY_LENGTH];
            _rng.GetBytes(key);

            // Now we initialize a Blowfish ECB instance with this key.
            bfe = new BlowfishECB(key, 0, key.Length);

            // Check if this is a good key.
            if (bfe.IsWeakKey)
            {
                Console.WriteLine(Resources.BFDEMO_WEAK_KEY_DETECTED);
            }

            // Generate "plaintext" data.
            for (i = 0; i < plain.Length; i++)
            {
                plain[i] = (byte)i;
            }

            // Make sure that the output buffers are clean.
            Array.Clear(encrypted, 0, encrypted.Length);
            Array.Clear(decrypted, 0, decrypted.Length);

            // Encrypt this data in one pass.
            bfe.Encrypt(plain, 0, encrypted, 0, plain.Length);

            // Actually not necessary, but just to demonstrate things, we reuse
            // the already created instance with the same key.
            bfe.Initialize(key, 0, key.Length);

            // Decrypt the data.
            bfe.Decrypt(encrypted, 0, decrypted, 0, encrypted.Length);

            // Now compare that we actually got the right data back.
            for (i = 0; i < plain.Length; i++)
            {
                if (plain[i] != decrypted[i])
                {
                    // This should never happen.
                    Console.WriteLine(Resources.BFDEMO_DATAMISMATCH_1, i);
                    return;
                }
            }
            Console.WriteLine(Resources.BFDEMO_ECB_DECRYPT_OK);

            // Clean up the instance.
            bfe.Invalidate();
        }

        static void ShowBlowfishCBC()
        {
            // Most of the code here is similar to the one in TestBlowfishECB(),
            // yet we have to take care about managing the initialization vector
            // (IV), so here we go and create our IV. It needs to be stored
            // together with the encrypted data, since it's needed for decryption,
            // as you can see below.

            byte[] iv = new byte[BlowfishCBC.BLOCK_SIZE];

            _rng.GetBytes(iv);

            byte[] plain = new byte[BlowfishECB.BLOCK_SIZE * 100];

            byte[] encrypted = new byte[plain.Length];
            byte[] decrypted = new byte[plain.Length];

            byte[] key = new byte[BlowfishECB.MAX_KEY_LENGTH];
            _rng.GetBytes(key);

            BlowfishCBC bfc = new BlowfishCBC(key, 0, key.Length);

            for (int i = 0; i < plain.Length; i++)
            {
                plain[i] = (byte)i;
            }

            Array.Clear(encrypted, 0, encrypted.Length);
            Array.Clear(decrypted, 0, decrypted.Length);

            // Before we can start the encryption we need to set our IV. If we
            // don't do this then the resulting will be unpredictable.
            bfc.IV = iv;    // (the property _copies_ the content)

            bfc.Encrypt(plain, 0, encrypted, 0, plain.Length);

            // For decryption we have to do the same, so we set the IV back after
            // we initialized the instance again. This time we use the setter
            // method rather than the property.
            bfc.Initialize(key, 0, key.Length);
            
            bfc.SetIV(iv, 0);

            // Just for demo purposes we use a clone of our actual instance.
            bfc = (BlowfishCBC) bfc.Clone();
            bfc.Decrypt(encrypted, 0, decrypted, 0, encrypted.Length);

            for (int i = 0; i < plain.Length; i++)
            {
                if (plain[i] != decrypted[i])
                {
                    Console.WriteLine(Resources.BFDEMO_DATAMISMATCH_1, i);
                    return;
                }
            }

            // You may ask when you ever want to _get_ the IV value. It might be
            // necessary to do this to simply get a nice random value, but most of
            // the time it is applied in advanced streaming solutions.
            iv = bfc.IV;    // (again this is a _copy_)

            Console.WriteLine(Resources.BFDEMO_CBC_DECRYPT_OK);

            bfc.Invalidate();
        }

        static void ShowBlowfishCFB()
        {
            // CFB is the most convenient mode when it comes to block ciphers,
            // since there's no aligment work necessary, but just an
            // initialization vector to store alongside with the encrypted
            // data.

            byte[] iv = new byte[BlowfishCFB.BLOCK_SIZE];
            (new RNGCryptoServiceProvider()).GetBytes(iv);

            // (use a "raw" key here, although hashing with a digest algorithm
            // like SHA-256 is highly recommended)
            byte[] key = Encoding.UTF8.GetBytes("some key that is");

            BlowfishCFB bff = new BlowfishCFB(key, 0, key.Length);
            bff.IV = iv;
            
            byte[] plainText = Encoding.UTF8.GetBytes("This message was protected with Blowfish/CFB.");
            byte[] cipherText = new byte[plainText.Length];

            bff.Encrypt(plainText, 0, cipherText, 0, 11);   // (in two steps, just for fun)
            bff.Encrypt(plainText, 11, cipherText, 11, plainText.Length - 11);

            bff = new BlowfishCFB(key, 0, key.Length);
            bff.SetIV(iv, 0);

            byte[] decryptedText = new byte[plainText.Length];
            bff.Decrypt(cipherText, 0, decryptedText, 0, cipherText.Length);

            Console.WriteLine(Encoding.UTF8.GetString(decryptedText));

            bff.Invalidate();
        }

        #endregion

        #region Show BlowfishSimple

        static void ShowBlowfishSimple()
        {
            // show the most simple way to deal with BlowfishSimple

            String sPassw = "word";

            BlowfishSimple bfs = new BlowfishSimple(sPassw);

            String sOrig = "it doesn't get easier than this, so use BlowfishSimple";

            String sEnc = bfs.Encrypt(sOrig);

            Console.WriteLine(sEnc);
            Console.WriteLine(bfs.Decrypt(sEnc));

            String sDec = bfs.Decrypt(sEnc);

            if (sDec != sOrig)
            {
                Console.WriteLine(Resources.BFDEMO_SIMPLE_FLAW);
            }

            // This demonstrates of how to verify a password with the secue key
            // hash gathered out of the original password.

            String sChkSum = bfs.KeyChecksum;

            Console.WriteLine(sChkSum);

            if (BlowfishSimple.VerifyKey("not correct", sChkSum))
            {
                Console.WriteLine(Resources.BFDEMO_SIMPLE_UNEXPECTED_MATCH);
            }

            if (!BlowfishSimple.VerifyKey(sPassw, sChkSum))
            {
                Console.WriteLine(Resources.BFDEMO_SIMPLE_UNEXPECTED_MISMATCH);
            }
        }

        #endregion

        #region Show Java Interoperability

        static readonly string BFEASY_REF_PASSW = "secret";
        static readonly string BFEASY_REF_TEXT = "Protect me.";
        static readonly string BFEASY_REF_ENC = "e1c799a96e2b1f63f34927d5b7358d9c6fe4cc47ec31b79000642f5cd286007b";
        static readonly byte[] BFS_REF_KEY = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

        static void ShowJavaInterop()
        {   
            // demonstrate BlowfishEasy

            BlowfishEasy bfes = new BlowfishEasy(BFEASY_REF_PASSW);

            String enc = bfes.EncryptString(BFEASY_REF_TEXT);

            Console.WriteLine(enc);

            String dec = bfes.DecryptString(enc);
            Console.WriteLine(dec);

            // Here we try to decrypt material encrypted with BlowfishJ.
            dec = bfes.DecryptString(BFEASY_REF_ENC);
            Console.WriteLine(dec);

            // demonstrate BlowfishStream

            MemoryStream ms = new MemoryStream();

            BlowfishStream bfs = BlowfishStream.Create(
                ms,
                BlowfishStreamMode.Write,
                BFS_REF_KEY,
                0,
                BFS_REF_KEY.Length);
            
            const int c = 117;

            for (int i = 0; i < c; i++)
            {
                bfs.WriteByte((byte)i);
            }
            bfs.Close();

            byte[] encBytes = ms.ToArray();
            Console.WriteLine(Resources.BFDEMO_WRITTEN_TO_STREAM_2, c, encBytes.Length);

    #if DUMP_REF_STREAM
            // This data dump is used to have reference data for compatibility testing on
            // the Java side. It should actually not be necessary to recreate this data
            // (otherwise version-dependend compatibility might not be guaranteed anymore).
        
            for (i = 0; i < encBytes.Length;)
            {
                Console.Write("(byte)0x{0}", (encBytes[i++] & 0x0ff).ToString("x2"));
                Console.Write((0 == i % 6) ? ",\n" : ", ");
            }
            Console.WriteLine();
    #endif
            ms = new MemoryStream(encBytes);

            bfs = BlowfishStream.Create(
                ms,
                BlowfishStreamMode.Read,
                BFS_REF_KEY,
                0,
                BFS_REF_KEY.Length);

            for (int i = 0; i < c; i++)
            {
                if ((i & 0x0ff) != bfs.ReadByte())
                {
                    Console.WriteLine(Resources.BFDEMO_DECRYPT_ERROR_1, i);
                    return;
                }
            }

            if (-1 != bfs.ReadByte())
            {
                Console.WriteLine(Resources.BFDEMO_DECRYPT_OVERSIZED);
            }

            bfs.Close();

            Console.WriteLine(Resources.BFDEMO_STREAM_DECRYPT_OK);
        }   

        #endregion

        #region Show Performance Test

        static void ShowPerformance()
        {
            int maxloops = 30000;
            int blockc = 1000;

            BlowfishECB bfe = new BlowfishECB(new byte[0], 0, 0);
            byte[] buf = new byte[BlowfishECB.BLOCK_SIZE * blockc];

            Console.WriteLine(Resources.BFDEMO_RUNNING_PERFORMANCE);

            long tm = DateTime.Now.Ticks;

            for (int loop = 0; loop < maxloops; loop++)
            {
                bfe.Encrypt(buf, 0, buf, 0, buf.Length);
            }

            long total = maxloops * buf.Length;

            tm = DateTime.Now.Ticks - tm;
            tm /= 10 * 1000;
            if (0 == tm) tm = 1L;

            long rate = (total * 1000) / tm;

            Console.WriteLine(Resources.BFDEMO_SPEED_RESULT_1, rate);
        }

        #endregion

        #region Show Blowfish Algorithm Implementation

        public static string HexPrint(byte[] buf)
        {
            StringBuilder result = new StringBuilder(buf.Length * 3);

            for (int i = 0, c = buf.Length; i < c; i++)
            {
                if (0 < i) result.Append(' ');
                result.Append(buf[i].ToString("x2"));
            }
            return result.ToString();
        }

        static SymmetricAlgorithm MakeAlgo(bool useBlowfish)
        {
            SymmetricAlgorithm result = (useBlowfish) ? new BlowfishAlgorithm() : SymmetricAlgorithm.Create();
            result.Mode = CipherMode.CBC;

            if (useBlowfish) result.KeySize = 40;
            result.GenerateKey();
            result.GenerateIV();
            result.Padding = PaddingMode.PKCS7;

            return result;
        }

        static void ShowBlowfishAlgorithm()
        {
            // set up the algorithm (set to false to go with AES for comparison purposes)
            SymmetricAlgorithm alg = MakeAlgo(true);

            // we encrypt and decrypt from and to a memory stream, so first we have to set up a
            // source (by writing some bytes to it) and a target stream
            MemoryStream inStream = new MemoryStream();
            for (int i = 0; i < 11; i++)
            {
                inStream.WriteByte((byte)i);
            }
            inStream.Position = 0;  // need to reset it for the following reading
            MemoryStream outStream = new MemoryStream();

            // now we create a crypto stream, to show that our BlowfishAlgorithm plays together
            // with a standard .NET framework security component
            CryptoStream encStream = new CryptoStream(
                outStream, 
                alg.CreateEncryptor(), 
                CryptoStreamMode.Write);

            // write data from our input stream to the encrypted stream (which then will finally
            // put it into our output stream) by using a small buffer (as it it is done usually)
            byte[] buf = new byte[3];
            while (inStream.Position < inStream.Length)
            {
                int read = inStream.Read(buf, 0, buf.Length);
                encStream.Write(buf, 0, read);
            }
            encStream.Close();

            // show what we got for the encrypted data
            byte[] encData = outStream.ToArray();
            Console.WriteLine("plain    : " + HexPrint(inStream.ToArray()));
            Console.WriteLine("encrypted: " + HexPrint(encData));

            // decrypt the encrypted data, with the an input stream now set up with the
            // encrypted data and being passed to the decryption stream
            outStream = new MemoryStream();

            CryptoStream decStream = new CryptoStream(
                new MemoryStream(encData),
                alg.CreateDecryptor(),
                CryptoStreamMode.Read);

            while (outStream.Position < encData.Length)
            {
                int read = decStream.Read(buf, 0, buf.Length);
                if (0 == read) break;
                outStream.Write(buf, 0, read);
            }
            decStream.Close();

            byte[] decData = outStream.ToArray();
            Console.WriteLine("decrypted: " + HexPrint(decData));

            // verify that we got the right data back by simulating and comparing the
            // original input data
            for (int i = 0; i < 11; i++)
            {
                if (decData[i] != i)
                {
                    Console.WriteLine("decryption error!");
                    break;
                }
            }
        }

        #endregion

        /// <summary>The application entry point.</summary>
        public static void Main()
        {
            //ShowBlowfishECB();
            //ShowBlowfishCBC();
            //ShowBlowfishCFB();
            ShowBlowfishSimple();
            //ShowJavaInterop();
            //ShowBlowfishAlgorithm();
            //ShowPerformance();
        }
    }
}
