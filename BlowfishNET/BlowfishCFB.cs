/* 
  Copyright 2001-2007 Markus Hahn 
  All rights reserved. See documentation for license details.  
*/

using System;

namespace BlowfishNET
{

    /// <summary>Blowfish CFB implementation.</summary>
    /// <remarks>Use this class to encrypt or decrypt byte arrays in CFB (Cipher Feedback) mode.
    /// Useful if you don't want to deal with padding of blocks (in comparsion to CBC), however
    /// a safe initialization vector (IV) is still needed. Notice that the data does not have to
    /// be block-aligned in comparsion to ECB and CBC, so byte-per-byte streaming is possible.
    /// </remarks>
    public class BlowfishCFB : BlowfishECB
    {
        byte[] iv = new byte[BLOCK_SIZE];
        int ivBytesLeft = 0;

        /// <summary>The current initialization vector (IV), which measures one block.</summary>
        public byte[] IV
        {
            set
            {
                SetIV(value, 0);
            }

            get
            {
                byte[] result = new byte[BLOCK_SIZE];
                GetIV(result, 0);
                return result;
            }
        }

        /// <summary>Sets the initialization vector (IV) with an offset.</summary>
        /// <param name="buf">The buffer containing the new IV material.</param>
        /// <param name="ofs">Where the IV material starts.</param>
        public void SetIV(byte[] buf, int ofs)
        {
            Array.Copy(buf, ofs, this.iv, 0, this.iv.Length);
            this.ivBytesLeft = 0;
        }

        /// <summary>Gets the current IV material (of the size of one block).</summary>
        /// <param name="buf">The buffer to copy the IV to.</param>
        /// <param name="ofs">Where to start copying.</param>
        public void GetIV(byte[] buf, int ofs)
        {
            Array.Copy(this.iv, 0, buf, ofs, this.iv.Length);
        }

        /// <summary>Default constructor.</summary>
        /// <remarks>The IV needs to be assigned after the instance has been created!</remarks>
        /// <see cref="BlowfishNET.BlowfishECB.Initialize"/>
        public BlowfishCFB(byte[] key, int ofs, int len) : base(key, ofs, len)
        {
        }

        /// <summary>Zero key constructor.</summary>
        /// <remarks>After construction you need to initialize the instance and then apply the IV.</remarks>
        public BlowfishCFB() : base(null, 0, 0)
        {
        }

        /// <see cref="BlowfishNET.BlowfishECB.Invalidate"/>
        public new void Invalidate()
        {
            base.Invalidate();

            Array.Clear(this.iv, 0, this.iv.Length);
        }

        /// <see cref="BlowfishNET.BlowfishECB.Encrypt"/>
        public new int Encrypt(
            byte[] dataIn,
            int posIn,
            byte[] dataOut,
            int posOut,
            int count)
        {
            int end = posIn + count;
            
            byte[] iv = this.iv;

            int ivBytesLeft = this.ivBytesLeft;
            int ivPos = iv.Length - ivBytesLeft;

            // consume what's left in the IV buffer, but make sure to keep the new
            // ciphertext in a round-robin fashion (since it represents the new IV)
            if (ivBytesLeft >= count)
            {
                // what we have is enough to deal with the request
                for (; posIn < end; posIn++, posOut++, ivPos++)
                {
                    iv[ivPos] = dataOut[posOut] = (byte)(dataIn[posIn] ^ iv[ivPos]);
                }
                this.ivBytesLeft = iv.Length - ivPos;
                return count;
            }
            for (; ivPos < BLOCK_SIZE; posIn++, posOut++, ivPos++)
            {
                iv[ivPos] = dataOut[posOut] = (byte)(dataIn[posIn] ^ iv[ivPos]);
            }
            count -= ivBytesLeft;

            uint[] sbox1 = this.sbox1;
            uint[] sbox2 = this.sbox2;
            uint[] sbox3 = this.sbox3;
            uint[] sbox4 = this.sbox4;

            uint[] pbox = this.pbox;

            uint pbox00 = pbox[0];
            uint pbox01 = pbox[1];
            uint pbox02 = pbox[2];
            uint pbox03 = pbox[3];
            uint pbox04 = pbox[4];
            uint pbox05 = pbox[5];
            uint pbox06 = pbox[6];
            uint pbox07 = pbox[7];
            uint pbox08 = pbox[8];
            uint pbox09 = pbox[9];
            uint pbox10 = pbox[10];
            uint pbox11 = pbox[11];
            uint pbox12 = pbox[12];
            uint pbox13 = pbox[13];
            uint pbox14 = pbox[14];
            uint pbox15 = pbox[15];
            uint pbox16 = pbox[16];
            uint pbox17 = pbox[17];

            // now load the current IV into 32bit integers for speed
            uint hi = (((uint)iv[0]) << 24) |
                      (((uint)iv[1]) << 16) |
                      (((uint)iv[2]) <<  8) |
                              iv[3];

            uint lo = (((uint)iv[4]) << 24) |
                      (((uint)iv[5]) << 16) |
                      (((uint)iv[6]) <<  8) |
                              iv[7];

            // we deal with the even part first
            int rest = count % BLOCK_SIZE;
            end -= rest;

            for (;;)
            {
                // need to create new IV material no matter what
                hi ^= pbox00;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox01;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox02;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox03;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox04;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox05;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox06;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox07;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox08;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox09;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox10;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox11;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox12;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox13;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox14;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox15;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox16;

                uint swap = lo ^ pbox17;
                lo = hi;
                hi = swap;

                if (posIn >= end)
                {
                    // exit right in the middle so we always have new IV material for the rest below
                    break;
                }

                hi ^= (((uint)dataIn[posIn    ]) << 24) |
                      (((uint)dataIn[posIn + 1]) << 16) |
                      (((uint)dataIn[posIn + 2]) <<  8) |
                              dataIn[posIn + 3];

                lo ^= (((uint)dataIn[posIn + 4]) << 24) |
                      (((uint)dataIn[posIn + 5]) << 16) |
                      (((uint)dataIn[posIn + 6]) <<  8) |
                              dataIn[posIn + 7];

                posIn += 8;

                // now stream out the whole block
                dataOut[posOut    ] = (byte)(hi >> 24);
                dataOut[posOut + 1] = (byte)(hi >> 16);
                dataOut[posOut + 2] = (byte)(hi >>  8);
                dataOut[posOut + 3] = (byte) hi       ;

                dataOut[posOut + 4] = (byte)(lo >> 24);
                dataOut[posOut + 5] = (byte)(lo >> 16);
                dataOut[posOut + 6] = (byte)(lo >>  8);
                dataOut[posOut + 7] = (byte) lo       ;

                posOut += 8;
            }

            // store back the new IV
            iv[0] = (byte)(hi >> 24);
            iv[1] = (byte)(hi >> 16);
            iv[2] = (byte)(hi >>  8);
            iv[3] = (byte) hi       ;
            iv[4] = (byte)(lo >> 24);
            iv[5] = (byte)(lo >> 16);
            iv[6] = (byte)(lo >>  8);
            iv[7] = (byte) lo       ;

            // emit the rest
            for (int i = 0; i < rest; i++)
            {
                iv[i] = dataOut[posOut + i] = (byte)(dataIn[posIn + i] ^ iv[i]);
            }

            this.ivBytesLeft = iv.Length - rest;

            return count;
        }

        /// <see cref="BlowfishNET.BlowfishECB.Decrypt"/>
        public new int Decrypt(
            byte[] dataIn,
            int posIn,
            byte[] dataOut,
            int posOut,
            int count)
        {
            // same as above except that the ciphertext (input data) is what we keep...

            int end = posIn + count;

            byte[] iv = this.iv;

            int ivBytesLeft = this.ivBytesLeft;
            int ivPos = iv.Length - ivBytesLeft;

            if (ivBytesLeft >= count)
            {
                for (; posIn < end; posIn++, posOut++, ivPos++)
                {
                    int b = dataIn[posIn];
                    dataOut[posOut] = (byte)(b ^ iv[ivPos]);
                    dataIn[posIn] = (byte)b;
                }
                this.ivBytesLeft = iv.Length - ivPos;
                return count;
            }
            for (; ivPos < BLOCK_SIZE; posIn++, posOut++, ivPos++)
            {
                iv[ivPos] = dataOut[posOut] = (byte)(dataIn[posIn] ^ iv[ivPos]);
            }
            count -= ivBytesLeft;

            uint[] sbox1 = this.sbox1;
            uint[] sbox2 = this.sbox2;
            uint[] sbox3 = this.sbox3;
            uint[] sbox4 = this.sbox4;

            uint[] pbox = this.pbox;

            uint pbox00 = pbox[0];
            uint pbox01 = pbox[1];
            uint pbox02 = pbox[2];
            uint pbox03 = pbox[3];
            uint pbox04 = pbox[4];
            uint pbox05 = pbox[5];
            uint pbox06 = pbox[6];
            uint pbox07 = pbox[7];
            uint pbox08 = pbox[8];
            uint pbox09 = pbox[9];
            uint pbox10 = pbox[10];
            uint pbox11 = pbox[11];
            uint pbox12 = pbox[12];
            uint pbox13 = pbox[13];
            uint pbox14 = pbox[14];
            uint pbox15 = pbox[15];
            uint pbox16 = pbox[16];
            uint pbox17 = pbox[17];

            uint hi = (((uint)iv[0]) << 24) |
                      (((uint)iv[1]) << 16) |
                      (((uint)iv[2]) <<  8) |
                              iv[3];

            uint lo = (((uint)iv[4]) << 24) |
                      (((uint)iv[5]) << 16) |
                      (((uint)iv[6]) <<  8) |
                              iv[7];

            int rest = count % BLOCK_SIZE;
            end -= rest;

            for (; ; )
            {
                hi ^= pbox00;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox01;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox02;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox03;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox04;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox05;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox06;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox07;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox08;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox09;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox10;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox11;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox12;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox13;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox14;
                lo ^= (((sbox1[(int)(hi >> 24)] + sbox2[(int)((hi >> 16) & 0x0ff)]) ^ sbox3[(int)((hi >> 8) & 0x0ff)]) + sbox4[(int)(hi & 0x0ff)]) ^ pbox15;
                hi ^= (((sbox1[(int)(lo >> 24)] + sbox2[(int)((lo >> 16) & 0x0ff)]) ^ sbox3[(int)((lo >> 8) & 0x0ff)]) + sbox4[(int)(lo & 0x0ff)]) ^ pbox16;

                uint swap = lo ^ pbox17;
                lo = hi;
                hi = swap;

                if (posIn >= end)
                {
                    break;
                }

                uint chi = (((uint)dataIn[posIn]    ) << 24) |
                           (((uint)dataIn[posIn + 1]) << 16) |
                           (((uint)dataIn[posIn + 2]) <<  8) |
                                   dataIn[posIn + 3];
                
                uint clo = (((uint)dataIn[posIn + 4]) << 24) |
                           (((uint)dataIn[posIn + 5]) << 16) |
                           (((uint)dataIn[posIn + 6]) <<  8) |
                                   dataIn[posIn + 7];

                posIn += 8;

                hi ^= chi;
                lo ^= clo;

                dataOut[posOut]     = (byte)(hi >> 24);
                dataOut[posOut + 1] = (byte)(hi >> 16);
                dataOut[posOut + 2] = (byte)(hi >>  8);
                dataOut[posOut + 3] = (byte) hi;

                dataOut[posOut + 4] = (byte)(lo >> 24);
                dataOut[posOut + 5] = (byte)(lo >> 16);
                dataOut[posOut + 6] = (byte)(lo >>  8);
                dataOut[posOut + 7] = (byte) lo;

                posOut += 8;

                hi = chi;
                lo = clo;
            }

            iv[0] = (byte)(hi >> 24);
            iv[1] = (byte)(hi >> 16);
            iv[2] = (byte)(hi >>  8);
            iv[3] = (byte) hi;
            iv[4] = (byte)(lo >> 24);
            iv[5] = (byte)(lo >> 16);
            iv[6] = (byte)(lo >>  8);
            iv[7] = (byte) lo;

            for (int i = 0; i < rest; i++)
            {
                int b = dataIn[posIn + i];
                dataOut[posOut + i] = (byte)(b ^ iv[i]);
                iv[i] = (byte)b;
            }

            this.ivBytesLeft = iv.Length - rest;

            return count;
        }

        /// <see cref="BlowfishNET.BlowfishECB.Clone"/>
        public new object Clone()
        {
            BlowfishCFB result;

            result = new BlowfishCFB();

            result.pbox = (uint[])this.pbox.Clone();

            result.sbox1 = (uint[])this.sbox1.Clone();
            result.sbox2 = (uint[])this.sbox2.Clone();
            result.sbox3 = (uint[])this.sbox3.Clone();
            result.sbox4 = (uint[])this.sbox4.Clone();

            result.block = (byte[])this.block.Clone();

            result.isWeakKey = this.isWeakKey;

            result.iv = (byte[])this.iv.Clone();

            return result;
        }
    }
}
