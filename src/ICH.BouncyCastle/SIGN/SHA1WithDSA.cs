using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace ICH.BouncyCastle
{
    public class SHA1WithDSA
    {
        public static string GenerateSignature(string data, AsymmetricKeyParameter privateKey)
        {
            var byteData = Encoding.UTF8.GetBytes(data);
            var normalSig = SignerUtilities.GetSigner("SHA1WithDSA");
            normalSig.Init(true, privateKey);
            normalSig.BlockUpdate(byteData, 0, data.Length);
            var normalResult = normalSig.GenerateSignature();
            return Base64.ToBase64String(normalResult);
        }

        public static bool VerifySignature(string data, string sign, AsymmetricKeyParameter publicKey)
        {
            var signBytes = Base64.Decode(sign);
            var plainBytes = Encoding.UTF8.GetBytes(data);
            var verifier = SignerUtilities.GetSigner("SHA1WithDSA");
            verifier.Init(false, publicKey);
            verifier.BlockUpdate(plainBytes, 0, plainBytes.Length);

            return verifier.VerifySignature(signBytes);
        }
    }
}
