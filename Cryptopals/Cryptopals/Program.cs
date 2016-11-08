using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

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

        static readonly Random Rng = new Random();

        static readonly byte[] ConstantKeyOracleKey = new byte[16];


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

            Rng.NextBytes(ConstantKeyOracleKey);
        }

        //TODO: y I did this??
        static string HexToBase64(string hex)
        {
            StringBuilder sb = new StringBuilder();

            int left_val = 0, left_bits = 0;

            for (int i = 0; i < hex.Length; i += 2)
            {
                int b = int.Parse(hex.Substring(i, 2), System.Globalization.NumberStyles.AllowHexSpecifier);
                int r = b & ((1 << (2 + left_bits)) - 1);

                sb.Append(Base64[(left_val << (6 - left_bits)) + ((b - r) >> (2 + left_bits))]);
                left_val = r;
                left_bits += 2;

                if (left_bits == 6)
                {
                    sb.Append(Base64[left_val]);
                    left_bits = left_val = 0;
                }
            }

            if (left_bits > 0)
                sb.Append(Base64[(left_val << (6 - left_bits))]);

            int pad = hex.Length % 3;
            if (pad == 1) sb.Append("=");
            else if (pad == 2) sb.Append("==");

            return sb.ToString();
        }

        //TODO: do this personally?
        static string Base64ToHex(string base64)
        {
            return EncodeHex(Convert.FromBase64String(base64));
        }

        static void TestHexToBase64()
        {
            System.Diagnostics.Debug.Assert(HexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") ==
                "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

            System.Diagnostics.Debug.Assert(HexToBase64(EncodeHex(DecodeASCII("any carnal pleasure"))) == "YW55IGNhcm5hbCBwbGVhc3VyZQ==");
            System.Diagnostics.Debug.Assert(HexToBase64(EncodeHex(DecodeASCII("any carnal pleasure."))) == "YW55IGNhcm5hbCBwbGVhc3VyZS4=");

            System.Diagnostics.Debug.Assert(EncodeASCII(DecodeHex(Base64ToHex("YW55IGNhcm5hbCBwbGVhc3VyZQ=="))) == "any carnal pleasure");
        }

        static byte[] DecodeASCII(string str)
        {
            return System.Text.Encoding.ASCII.GetBytes(str);
        }

        static string EncodeASCII(byte[] bytes)
        {
            return System.Text.Encoding.ASCII.GetString(bytes);
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
            for (int i = 0; i < str.Length; i += 2)
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

        static byte[] XorRepeated(byte[] msg, byte[] key)
        {
            byte[] coded = new byte[msg.Length];
            for (int i = 0; i < msg.Length; i++)
                coded[i] = (byte)(msg[i] ^ key[i % key.Length]);
            return coded;
        }

        static void TestXor()
        {
            System.Diagnostics.Debug.Assert(
                EncodeHex(Xor(
                    DecodeHex("1c0111001f010100061a024b53535009181c"),
                    DecodeHex("686974207468652062756c6c277320657965"))) ==
                "746865206b696420646f6e277420706c6179");
        }

        static void TestXorRepeated()
        {
            System.Diagnostics.Debug.Assert(
               EncodeHex(XorRepeated(
                   DecodeASCII("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"),
                   DecodeASCII("ICE"))) ==
               "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
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
            for (int i = 0; i < str.Length; i++)
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

        static int Hamming(byte[] a, byte[] b)
        {
            byte[] c = Xor(a, b);
            int dist = 0;
            for (int i = 0; i < c.Length; i++)
            {
                byte x = c[i];
                for (int j = 0; j < 8; j++)
                {
                    dist += x & 1;
                    x >>= 1;
                }
            }

            return dist;
        }

        static void TestHamming()
        {
            System.Diagnostics.Debug.Assert(Hamming(DecodeASCII("this is a test"),
                                                    DecodeASCII("wokka wokka!!!")) == 37);
        }

        static byte[] PadBlock(byte[] block, int target_len)
        {
            byte pad_byte = (byte)(target_len - block.Length);

            byte[] result = new byte[target_len];
            for (int i = 0; i < target_len; i++)
            {
                if (i < block.Length) result[i] = block[i];
                else result[i] = pad_byte;
            }
            return result;
        }

        static byte[] Unpad(byte[] msg)
        {
            int num_pad = msg[msg.Length - 1];
            byte[] result = new byte[msg.Length - num_pad];
            Array.Copy(msg, 0, result, 0, result.Length);
            return result;
        }

        static List<byte[]> BreakIntoBlocksWithPadding(byte[] msg, int block_size)
        {
            List<byte[]> blocks = new List<byte[]>();

            for (int i = 0; i < msg.Length; i += block_size)
            {
                byte[] b = new byte[Math.Min(block_size, msg.Length - i)];
                Array.Copy(msg, i, b, 0, b.Length);
                blocks.Add(b);
            }

            blocks[blocks.Count - 1] = PadBlock(blocks[blocks.Count - 1], block_size);

            return blocks;
        }

        static byte[] GatherBlocks(List<byte[]> blocks, int block_size)
        {
            byte[] msg = new byte[blocks.Count * block_size];
            for (int i = 0; i < blocks.Count; i++)
                Array.Copy(blocks[i], 0, msg, i * block_size, block_size);

            return msg;            
        }

        static byte[] DecypherSingleByteXor(byte[] msg, out byte key, out double best_diff)
        {
            double min_freq_diff = double.MaxValue;
            byte best_x = 0;

            for (byte x = 0; x < 255; x++)
            {
                byte[] dec_msg = XorSingleByte(msg, x);

                double[] freq = GetStringCharFreq(dec_msg);
                double freq_diff = GetFreqDifference(EnglishCharFreq, freq);
                if (freq_diff < min_freq_diff)
                {
                    min_freq_diff = freq_diff;
                    best_x = x;
                }
            }

            best_diff = min_freq_diff;
            key = best_x;
            return XorSingleByte(msg, key);
        }

        static string FindLineCodedBySingleByteXor(string filename)
        {
            string[] lines = File.ReadAllLines(filename);

            List<(string, double)> list = new List<(string, double)>();

            foreach (string line in lines)
            {
                double diff;
                byte key;
                string dec = System.Text.Encoding.ASCII.GetString(DecypherSingleByteXor(DecodeHex(line), out key, out diff));
                list.Add((dec, diff));
            }

            var slist = list.OrderBy(x => x.Item2).ToList();

            return slist[0].Item1;
        }

        static byte[] ReadBytesFromBase64LinesFile(string filename)
        {
            string[] lines = File.ReadAllLines(filename);
            StringBuilder sb = new StringBuilder();
            foreach (var line in lines)
                sb.Append(line.Trim());
            byte[] msg = DecodeHex(Base64ToHex(sb.ToString()));

            return msg;
        }

        static List<(string key, string message)> BreakRepeatedXor(string filename, int min_key_size, int max_key_size)
        {
            const int NBlocksForHamming = 8;
            const int NTopBest = 5;

            byte[] msg = ReadBytesFromBase64LinesFile(filename);

            List<(double dist, int key_size)> ks_dist = new List<(double dist, int key_size)>();

            for (int key_size = min_key_size; key_size < max_key_size; key_size++)
            {
                List<byte[]> blocks = new List<byte[]>();
                for (int i = 0; i < NBlocksForHamming; i++)
                {
                    byte[] b = new byte[key_size];
                    Array.Copy(msg, i * key_size, b, 0, key_size);
                    blocks.Add(b);
                }
                double dist = 0;
                for (int i = 0; i < blocks.Count; i++)
                    for (int j = 0; j < i; j++)
                        dist += Hamming(blocks[i], blocks[j]);

                dist /= (double)key_size;

                ks_dist.Add((dist, key_size));
            }

            var sort_ks_dist = ks_dist.OrderBy(x => x.dist).Take(NTopBest).ToList();
            List<(string key, string message)> results = new List<(string key, string message)>();
            foreach (int key_size in sort_ks_dist.Select(x => x.key_size))
            {
                List<byte>[] blocks = new List<byte>[key_size];
                for (int i = 0; i < key_size; i++)
                    blocks[i] = new List<byte>();

                for (int i = 0; i < msg.Length; i += key_size)
                {
                    for (int j = 0; j < key_size && j < msg.Length - i; j++)
                        blocks[j].Add(msg[i + j]);
                }

                byte[] full_key = new byte[key_size];
                for (int i = 0; i < key_size; i++)
                {
                    double single_byte_diff;
                    byte key;
                    DecypherSingleByteXor(blocks[i].ToArray(), out key, out single_byte_diff);
                    full_key[i] = key;
                }

                results.Add((EncodeASCII(full_key), EncodeASCII(XorRepeated(msg, full_key))));
                //Console.WriteLine($"Keysize {key_size}, key: {EncodeASCII(full_key)}, msg: " + new string(EncodeASCII(XorRepeated(msg, full_key)).Take(32).ToArray()));
                //Console.ReadLine();
            }

            return results;
        }

        static byte[] DecryptAES_ECB(byte[] msg, byte[] key)
        {
            var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.BlockSize = 128;
            aes.KeySize = 128;
            aes.Padding = PaddingMode.None; //NOTE: crucial for correct one-block-at-a-time encoding/decoding?
            aes.Key = key;

            var decr = aes.CreateDecryptor();

            List<byte[]> blocks = BreakIntoBlocksWithPadding(msg, 16);
            List<byte[]> result_blocks = new List<byte[]>();
            foreach(var b in blocks)
            {
                byte[] dec_b = new byte[16];
                decr.TransformBlock(b, 0, 16, dec_b, 0);
                result_blocks.Add(dec_b);
            }
            
            return GatherBlocks(result_blocks, 16);
        }

        static byte[] EncryptAES_ECB(byte[] msg, byte[] key)
        {
            var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.BlockSize = 128;
            aes.KeySize = 128;
            aes.Padding = PaddingMode.None;
            aes.Key = key;

            var encr = aes.CreateEncryptor();
            List<byte[]> blocks = BreakIntoBlocksWithPadding(msg, 16);
            List<byte[]> result_blocks = new List<byte[]>();
            foreach (var b in blocks)
            {
                byte[] enc_b = new byte[16];
                encr.TransformBlock(b, 0, 16, enc_b, 0);
                result_blocks.Add(enc_b);
            }

            return GatherBlocks(result_blocks, 16);
        }

        static byte[] EncryptAES_CBC(byte[] msg, byte[] key, byte[] iv)
        {
            int block_size = key.Length;

            List<byte[]> blocks = BreakIntoBlocksWithPadding(msg, block_size);
            byte[] result = new byte[blocks.Count * block_size];
            byte[] v = iv;

            for (int i = 0; i < blocks.Count; i++)
            {
                byte[] b = blocks[i];
                b = Xor(b, v);
                byte[] eb = EncryptAES_ECB(b, key);                
                Array.Copy(eb, 0, result, i * block_size, block_size);
                v = eb;
            }

            return result;
        }

        static byte[] DecryptAES_CBC(byte[] msg, byte[] key, byte[] iv)
        {
            int block_size = key.Length;

            List<byte[]> blocks = BreakIntoBlocksWithPadding(msg, block_size);
            byte[] result = new byte[blocks.Count * block_size];
            byte[] v = iv;

            for (int i = 0; i < blocks.Count; i++)
            {
                byte[] b = blocks[i];
                byte[] db = DecryptAES_ECB(b, key);
                db = Xor(db, v);
                Array.Copy(db, 0, result, i * block_size, block_size);
                v = b;
            }

            return result;
        }

        static void DetectECB(string filename)
        {
            const int block_size = 16;

            HashSet<int> suspicios_idx = new HashSet<int>();

            string[] lines = File.ReadAllLines(filename);
            for (int k = 0; k < lines.Length; k++)
            {
                string hex = lines[k];
                byte[] msg = DecodeHex(hex);
                var blocks = BreakIntoBlocksWithPadding(msg, block_size);

                for (int i = 0; i < blocks.Count; i++)
                    for (int j = 0; j < i; j++)
                        if(Hamming(blocks[i], blocks[j]) == 0)                        
                            suspicios_idx.Add(k);                        
            }

            Console.WriteLine(String.Join(", ", suspicios_idx.ToArray()));
        }

        static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] c = new byte[a.Length + b.Length];
            Array.Copy(a, 0, c, 0, a.Length);
            Array.Copy(b, 0, c, a.Length, b.Length);
            return c;
        }
        

        static byte[] EncryptionOracle(byte[] msg)
        {
            byte[] append_before = new byte[Rng.Next(5, 11)];
            byte[] append_after = new byte[Rng.Next(5, 11)];
            msg = Concat(Concat(append_before, msg), append_after);            

            byte[] key = new byte[16];
            Rng.NextBytes(key);

            if (Rng.NextDouble() < 0.5)
            {
                Console.WriteLine("Coding with ECB");
                return EncryptAES_ECB(msg, key);
            }
            else
            {
                Console.WriteLine("Coding with CBC");
                byte[] iv = new byte[16];
                Rng.NextBytes(iv);
                return EncryptAES_CBC(msg, key, iv);
            }            
        }

        static byte[] ConstantKeyOracle(byte[] injected)
        {
            byte[] unknown = DecodeHex(Base64ToHex("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"));

            string spoiler = EncodeASCII(unknown);

            byte[] msg = Concat(injected, unknown);
            return EncryptAES_ECB(msg, ConstantKeyOracleKey);
        }

        static void IsECBOrCBC(Func<byte[], byte[]> oracle)
        {
            const int block_size = 16;
            string input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

            for (int k = 0; k < 8; k++)
            {
                Console.WriteLine($"Testing iter {k}");
                byte[] coded = oracle(DecodeASCII(input));
                var blocks = BreakIntoBlocksWithPadding(coded, block_size);

                for (int i = 0; i < blocks.Count; i++)
                    for (int j = 0; j < i; j++)
                        if (Hamming(blocks[i], blocks[j]) == 0)
                        {
                            Console.WriteLine("ECB detected!");
                            goto Exit;
                        }


                Exit: { }                
            }            
        }

        static string BreakConstantKeyOracle(Func<byte[], byte[]> oracle)
        {
            //Discover block size and if it is using ECB
            StringBuilder inj = new StringBuilder();            

            int block_size;
            for(block_size = 1; ; block_size++)
            {
                inj.Append("AA");
                byte[] crypt = oracle(DecodeASCII(inj.ToString()));
                List<byte[]> cbs = BreakIntoBlocksWithPadding(crypt, block_size);
                if(Hamming(cbs[0], cbs[1]) == 0)                                    
                    break;                                
            }

            //Break one byte at a time
            StringBuilder unknown = new StringBuilder();
            for (int i = 0; ; i++)
            {
                inj.Clear();
                for (int j = 0; j < block_size - 1 - (i % block_size); j++)
                    inj.Append("A");
                string sinj = inj.ToString();
                string sunknown = unknown.ToString();
                                
                List<byte[]> ucrypt_blocks = BreakIntoBlocksWithPadding(oracle(DecodeASCII(sinj)), block_size);

                int k = i / block_size;
                if (k >= ucrypt_blocks.Count) break;
                byte[] ucrypt = ucrypt_blocks[k];

                string t;
                if (k == 0) t = sinj + sunknown;
                else t = sunknown.Substring(sunknown.Length - block_size + 1);

                int x;   
                for (x = 0; x < 255; x++)
                {
                    byte[] crypt = oracle(DecodeASCII(t + (char)x)).Take(block_size).ToArray();
                    if (Hamming(ucrypt, crypt) == 0)
                    {
                        unknown.Append((char)x);
                        break;
                    }
                }
                if (x == 255) unknown.ToString();
            }              

            return unknown.ToString();
        }

        static void Main(string[] args)
        {
            TestHexToBase64();
            TestXor();
            TestXorRepeated();
            TestHamming();
            Console.WriteLine("Tests success!");

            //double diff = GetFreqDifference(EnglishCharFreq, GetStringCharFreq(System.Text.Encoding.ASCII.GetBytes("Cooking MCs like a pound of bacon".ToUpper())));
            //double diff;
            //byte key;
            //string dec = System.Text.Encoding.ASCII.GetString(DecypherSingleByteXor(DecodeHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"), out key, out diff));
            //double d = RankDistance(new[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, new[] {1, 2, 3, 5, 4 });

            //string s = FindLineCodedBySingleByteXor("4.txt");

            //int d = Hamming(DecodeASCII("this is a test"),
            //                DecodeASCII("wokka wokka!!!"));

            //var results = BreakRepeatedXor("6.txt", 2, 40);
            //Console.WriteLine(results[0].key);
            //Console.WriteLine();

            //Console.WriteLine(results[0].message);

            //Console.WriteLine(EncodeASCII(DecryptAES_ECB(ReadBytesFromBase64LinesFile("7.txt"), DecodeASCII("YELLOW SUBMARINE"))));

            //byte[] msg = EncryptAES_ECB(DecodeASCII("blablabla sdflsjlewrewsflskdjwefsd"), DecodeASCII("YELLOW SUBMARINE"));
            //string decr = EncodeASCII(DecryptAES_ECB(msg, DecodeASCII("YELLOW SUBMARINE")));

            //DetectECB("8.txt");

            //byte[] iv = new byte[16];
            //Rng.NextBytes(iv);
            //string test = EncodeASCII(Unpad(DecryptAES_CBC(EncryptAES_CBC(DecodeASCII("aaaaabbbbbbcccccccddddd  dsflkjwlekjsdlfnsdl lwj lsjdlf sjdlsjflwjelnfs lsdjf lskd lsnfl"), 
            //    DecodeASCII("YELLOW SUBMARINE"), iv),
            //    DecodeASCII("YELLOW SUBMARINE"), iv)));
            //string res = EncodeASCII(DecryptAES_CBC(ReadBytesFromBase64LinesFile("10.txt"), DecodeASCII("YELLOW SUBMARINE"), new byte[16]));
            //Console.WriteLine(res);

            //byte[] result = EncryptionOracle(DecodeASCII("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
            //IsECBOrCBC(EncryptionOracle);
            string decrypted = BreakConstantKeyOracle(ConstantKeyOracle);
            Console.WriteLine(decrypted);
            
            Console.ReadLine();
        }
    }
}
