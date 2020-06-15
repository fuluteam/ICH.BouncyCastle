using System;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace ICH.BouncyCastle
{
    public class HMACMD5
    {
public static string GeneratorKey()
{
    return HMAC.GeneratorKey("HMAC-MD5");
}

public static byte[] Compute(string data, string key)
{

    return HMAC.Compute(data, key, "HMAC-MD5");

    //or
    return HMAC.Compute(data, key, new MD5Digest());
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

    using (var hmacMd5 = new System.Security.Cryptography.HMACMD5(Encoding.UTF8.GetBytes(key)))
    {
        return hmacMd5.ComputeHash(Encoding.UTF8.GetBytes(data));
    }
}
    }
}
