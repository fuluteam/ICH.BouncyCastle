using System;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace ICH.BouncyCastle
{
    public class HMACSHA1
    {
        public static string GeneratorKey()
        {
            var kGen = GeneratorUtilities.GetKeyGenerator("HMac/SHA1");
            return Hex.ToHexString(kGen.GenerateKey());
        }

        public static byte[] Compute(string data, string key)
        {

            return HMAC.Compute(data, key, "HMac/SHA1");

            //or
            //return HMAC.Compute(data, key, new Sha1Digest());
        }

        /// <summary>
        /// 不使用BouncyCastle的写法
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] Compute2(string data, string key)
        {
            if (string.IsNullOrEmpty(data))
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (string.IsNullOrEmpty(key))
            {
                throw new ArgumentNullException(nameof(key));
            }

            using (var hmacSha1 = new System.Security.Cryptography.HMACSHA1(Encoding.UTF8.GetBytes(key)))
            {
                return hmacSha1.ComputeHash(Encoding.UTF8.GetBytes(data));
            }
        }
    }
}
