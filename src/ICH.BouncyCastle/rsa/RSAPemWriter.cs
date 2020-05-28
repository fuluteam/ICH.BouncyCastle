using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ICH.BouncyCastle
{
    public class RSAPemWriter
    {
        public static string WritePkcs1PrivateKey(string privateKey)
        {
            if (privateKey.StartsWith("-----BEGIN RSA PRIVATE KEY-----"))
            {
                return privateKey;
            }

            var akp = RSAUtilities.GetAsymmetricKeyParameterFormPrivateKey(privateKey);
            using (var sw = new StringWriter())
            {
                var pWrt = new PemWriter(sw);
                pWrt.WriteObject(akp);
                pWrt.Writer.Close();
                return sw.ToString();
            }
        }

        public static string WritePkcs8PrivateKey(string privateKey)
        {
            if (privateKey.StartsWith("-----BEGIN PRIVATE KEY-----"))
            {
                return privateKey;
            }

            var akp = RSAUtilities.GetAsymmetricKeyParameterFormAsn1PrivateKey(privateKey);

            using (var sw = new StringWriter())
            {
                var pWrt = new PemWriter(sw);
                var pkcs8 = new Pkcs8Generator(akp);
                pWrt.WriteObject(pkcs8);
                pWrt.Writer.Close();
                return sw.ToString();
            }
        }

        public static string WritePublicKey(string publicKey)
        {
            if (publicKey.StartsWith("-----BEGIN PUBLIC KEY-----"))
            {
                return publicKey;
            }
            var akp = RSAUtilities.GetAsymmetricKeyParameterFormPublicKey(publicKey);
            using (var sw = new StringWriter())
            {
                var pWrt = new PemWriter(sw);
                pWrt.WriteObject(akp);
                pWrt.Writer.Close();
                return sw.ToString();
            }
        }
    }
}
