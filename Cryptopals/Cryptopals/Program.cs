using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptopals
{
    class Program
    {
        static readonly char[] Base64;

        //Last is space
        static readonly double[] EnglishCharFreq =
        {
            8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
            6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074, 23.4
        };
      

        static Program()
        {
            //Base64
            Base64 = new char[64];
            for (int i = 0; i < 26; i++)
                Base64[i] = (char)('A' + i);
            for (int i = 0; i < 26; i++)
                Base64[26 + i] = (char)('a' + i);
            for (int i = 0; i < 10; i++)
                Base64[52 + i] = (char)('0' + i);
            Base64[62] = '+';
            Base64[63] = '/';

            NormalizeFreq(EnglishCharFreq);   
        }

        static string HexToBase64(string hex)
        {
            StringBuilder sb = new StringBuilder();
                        
            int left_val = 0, left_bits = 0;
            
            for (int i = 0; i < hex.Length; i+=2)
            {
                int b = int.Parse(hex.Substring(i, 2), System.Globalization.NumberStyles.AllowHexSpecifier);
                int r = b & ((1 << (2 + left_bits)) - 1);

                sb.Append(Base64[(left_val << (6 - left_bits)) + ((b - r) >> (2 + left_bits))]);
                left_val = r;
                left_bits += 2;
                
                if(left_bits == 6)
                {                    
                    sb.Append(Base64[left_val]);
                    left_bits = left_val = 0;                    
                }
            }

            if(left_bits != 0)            
                sb.Append(Base64[(left_val << (6 - left_bits))]);            

            return sb.ToString();
        }

        static void TestHexToBase64()
        {
            System.Diagnostics.Debug.Assert(HexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") ==
                "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        }

        static string EncodeHex(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
                sb.Append(bytes[i].ToString("x2"));
            return sb.ToString();            
        }

        static byte[] DecodeHex(string str)
        {
            byte[] bytes = new byte[str.Length / 2];
            for (int i = 0; i < str.Length; i+=2)            
                bytes[i / 2] = byte.Parse(str.Substring(i, 2), System.Globalization.NumberStyles.AllowHexSpecifier);
            return bytes;            
        }

        static byte[] Xor(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                throw new InvalidProgramException("Xor byte len differ");

            byte[] c = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                c[i] = (byte)(a[i] ^ b[i]);

            return c;            
        }

        static byte[] XorSingleByte(byte[] a, byte x)
        {
            byte[] b = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                b[i] = (byte)(a[i] ^ x);
            return b;
        }

        static void TestXor()
        {
            System.Diagnostics.Debug.Assert(
                EncodeHex(Xor(
                    DecodeHex("1c0111001f010100061a024b53535009181c"), 
                    DecodeHex("686974207468652062756c6c277320657965"))) ==
                "746865206b696420646f6e277420706c6179");
        }

        static void NormalizeFreq(double[] freq)
        {           
            double freqSum = 0;
            for (int i = 0; i < freq.Length; i++)
                freqSum += freq[i];
            for (int i = 0; i < freq.Length; i++)
                freq[i] /= freqSum;
        }

        static double[] GetStringCharFreq(byte[] str)
        {
            double[] freq = new double[27];
            for(int i = 0; i < str.Length; i++)
            {
                byte b = str[i];
                int idx;
                if (b == ' ') idx = 26;
                else idx = b - 'a';

                if (idx < 0 || idx > 26)
                    idx = b - 'A';
                if (idx < 0 || idx > 26)
                    continue;

                freq[idx]++;
            }

            NormalizeFreq(freq);
            return freq;
        }       
     

        static double GetFreqDifference(double[] eth, double[] prop)
        {
            double err = 0;
            for (int i = 0; i < prop.Length; i++)            
                err += Math.Pow(eth[i] - prop[i], 2);            
            return err;
        }

        static byte[] DecypherSingleByteXor(byte[] msg, out double best_diff)
        {
            double min_freq_diff = double.MaxValue;
            byte best_x = 0;

            for (byte x = 0; x < 255; x++)
            {
                byte[] dec_msg = XorSingleByte(msg, x);               

                double[] freq = GetStringCharFreq(dec_msg);
                double freq_diff = GetFreqDifference(EnglishCharFreq, freq);
                if(freq_diff < min_freq_diff)
                {
                    min_freq_diff = freq_diff;
                    best_x = x;                    
                }               
            }

            best_diff = min_freq_diff;
            return XorSingleByte(msg, best_x);
        }

        static string FindLineCodedBySingleByteXor(string filename)
        {
            string[] lines = File.ReadAllLines(filename);

            List<(string, double)> list = new List<(string, double)>();
            
            foreach(string line in lines)
            {
                double diff;
                string dec = System.Text.Encoding.ASCII.GetString(DecypherSingleByteXor(DecodeHex(line), out diff));
                list.Add((dec, diff));
            }

            var slist = list.OrderBy(x => x.Item2).ToList();

            return slist[0].Item1;
        }

        static void Main(string[] args)
        {
            TestHexToBase64();
            TestXor();

            //double diff = GetFreqDifference(EnglishCharFreq, GetStringCharFreq(System.Text.Encoding.ASCII.GetBytes("Cooking MCs like a pound of bacon".ToUpper())));
            //double diff;
            //string dec = System.Text.Encoding.ASCII.GetString(DecypherSingleByteXor(DecodeHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"), out diff));
            //double d = RankDistance(new[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, new[] {1, 2, 3, 5, 4 });

            string s = FindLineCodedBySingleByteXor("4.txt");

            Console.WriteLine("Tests success!");
            Console.ReadLine();
        }
    }
}
