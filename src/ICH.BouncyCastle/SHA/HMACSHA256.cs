using System;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace ICH.BouncyCastle
{
    public class HMACSHA256
    {
        public static string GeneratorKey()
        {
            return HMAC.GeneratorKey("HMac/SHA256");
        }

        public static byte[] Compute(string data, string key)
        {

            return HMAC.Compute(data, key, "HMac/SHA256");

            //or
            //return HMAC.Compute(data, key, new Sha256Digest());
        }

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
            
            using (var hmacSha256 = new System.Security.Cryptography.HMACSHA256(Encoding.UTF8.GetBytes(key)))
            {
                return hmacSha256.ComputeHash(Encoding.UTF8.GetBytes(data));
            }
        }
    }
}
