using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Utilities;

namespace ICH.BouncyCastle.Symmetry
{
    public class AES
    {
        public static byte[] GenerateKey(int keySize = 128)
        {
            var kg = GeneratorUtilities.GetKeyGenerator("AES");
            kg.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
            return kg.GenerateKey();
        }

        public static byte[] GenerateKey(string seed, string algorithm, int keySize = 128)
        {
            var kg = GeneratorUtilities.GetKeyGenerator("AES");
            var secureRandom = SecureRandom.GetInstance(algorithm);
            secureRandom.SetSeed(Strings.ToByteArray(seed));
            kg.Init(new KeyGenerationParameters(secureRandom, keySize));
            return kg.GenerateKey();
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="data">待加密原文数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">偏移量，ECB模式不用填写！</param>
        /// <param name="algorithm">密文算法</param>
        /// <returns>密文数据</returns>
        public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv, string algorithm)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var cipher = CipherUtilities.GetCipher(algorithm);
            if (iv == null)
            {
                cipher.Init(true, ParameterUtilities.CreateKeyParameter("AES", key));
            }
            else
            {
                cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", key), iv));
            }

            return cipher.DoFinal(data);
        }
        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="data">待解密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">偏移量，ECB模式不用填写！</param>
        /// <param name="algorithm">密文算法</param>
        /// <returns>未加密原文数据</returns>
        public static byte[] Decrypt(byte[] data, byte[] key, byte[] iv, string algorithm)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var cipher = CipherUtilities.GetCipher(algorithm);
            if (iv == null)
            {
                cipher.Init(false, ParameterUtilities.CreateKeyParameter("AES", key));
            }
            else
            {
                cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", key), iv));
            }
            return cipher.DoFinal(data);
        }
    }
}
