using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;

namespace ICH.BouncyCastle
{
    public class RSAKeyConverter
    {
        /// <summary>
        /// Pkcs1>>Pkcs8
        /// </summary>
        /// <param name="privateKey">Pkcs1私钥</param>
        /// <param name="format">是否转PEM格式</param>
        /// <returns></returns>
        public static string PrivateKeyPkcs1ToPkcs8(string privateKey, bool format = false)
        {
            var akp = AsymmetricKeyUtilities.GetAsymmetricKeyParameterFormPrivateKey(privateKey);
            if (format)
            {
                var sw = new StringWriter();
                var pWrt = new PemWriter(sw);
                var pkcs8 = new Pkcs8Generator(akp);
                pWrt.WriteObject(pkcs8);
                pWrt.Writer.Close();
                return sw.ToString();
            }
            else
            {
                var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(akp);
                return Base64.ToBase64String(privateKeyInfo.GetEncoded());
            }
        }

        /// <summary>
        /// Pkcs8>>Pkcs1
        /// </summary>
        /// <param name="privateKey">Pkcs8私钥</param>
        /// <param name="format">是否转PEM格式</param>
        /// <returns></returns>
        public static string PrivateKeyPkcs8ToPkcs1(string privateKey, bool format = false)
        {
            var akp = AsymmetricKeyUtilities.GetAsymmetricKeyParameterFormAsn1PrivateKey(privateKey);
            if (format)
            {
                var sw = new StringWriter();
                var pWrt = new PemWriter(sw);
                pWrt.WriteObject(akp);
                pWrt.Writer.Close();
                return sw.ToString();
            }
            else
            {
                var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(akp);
                return Base64.ToBase64String(privateKeyInfo.ParsePrivateKey().GetEncoded());
            }
        }

        /// <summary>
        /// 从Pkcs8私钥中提取公钥
        /// </summary>
        /// <param name="privateKey">Pkcs8私钥</param>
        /// <returns></returns>
        public static string GetPublicKeyFromPrivateKeyPkcs8(string privateKey)
        {
            var privateKeyInfo = PrivateKeyInfo.GetInstance(Asn1Object.FromByteArray(Base64.Decode(privateKey)));
            privateKey = Base64.ToBase64String(privateKeyInfo.ParsePrivateKey().GetEncoded());

            var instance = RsaPrivateKeyStructure.GetInstance(Base64.Decode(privateKey));

            var publicParameter = (AsymmetricKeyParameter)new RsaKeyParameters(false, instance.Modulus, instance.PublicExponent);

            var privateParameter = (AsymmetricKeyParameter)new RsaPrivateCrtKeyParameters(instance.Modulus, instance.PublicExponent, instance.PrivateExponent, instance.Prime1, instance.Prime2, instance.Exponent1, instance.Exponent2, instance.Coefficient);

            var keyPair = new AsymmetricCipherKeyPair(publicParameter, privateParameter);
            var subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);

            return Base64.ToBase64String(subjectPublicKeyInfo.GetEncoded());
        }

        /// <summary>
        /// 从Pkcs1私钥中提取公钥
        /// </summary>
        /// <param name="privateKey">Pkcs1私钥</param>
        /// <returns></returns>
        public static string GetPublicKeyFromPrivateKeyPkcs1(string privateKey)
        {
            var instance = RsaPrivateKeyStructure.GetInstance(Base64.Decode(privateKey));

            var publicParameter = (AsymmetricKeyParameter)new RsaKeyParameters(false, instance.Modulus, instance.PublicExponent);

            var privateParameter = (AsymmetricKeyParameter)new RsaPrivateCrtKeyParameters(instance.Modulus, instance.PublicExponent, instance.PrivateExponent, instance.Prime1, instance.Prime2, instance.Exponent1, instance.Exponent2, instance.Coefficient);

            var keyPair = new AsymmetricCipherKeyPair(publicParameter, privateParameter);
            var subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);

            return Base64.ToBase64String(subjectPublicKeyInfo.GetEncoded());
        }


        /// <summary>    
        /// RSA私钥格式转换
        /// </summary>    
        /// <returns></returns>   
        public static string GetPrivateKeyFromXml(string privateKey)
        {
            var doc = new XmlDocument();
            doc.LoadXml(privateKey);
            var modules = new BigInteger(1, Base64.Decode(doc.DocumentElement.GetElementsByTagName("Modulus")[0].InnerText));
            var publicExponent = new BigInteger(1, Base64.Decode(doc.DocumentElement.GetElementsByTagName("Exponent")[0].InnerText));
            var privateExponent = new BigInteger(1, Base64.Decode(doc.DocumentElement.GetElementsByTagName("D")[0].InnerText));
            var p = new BigInteger(1, Base64.Decode(doc.DocumentElement.GetElementsByTagName("P")[0].InnerText));
            var q = new BigInteger(1, Base64.Decode(doc.DocumentElement.GetElementsByTagName("Q")[0].InnerText));
            var dP = new BigInteger(1, Base64.Decode(doc.DocumentElement.GetElementsByTagName("DP")[0].InnerText));
            var dQ = new BigInteger(1, Base64.Decode(doc.DocumentElement.GetElementsByTagName("DQ")[0].InnerText));
            var qInv = new BigInteger(1, Base64.Decode(doc.DocumentElement.GetElementsByTagName("InverseQ")[0].InnerText));
            var akp = new RsaPrivateCrtKeyParameters(modules, publicExponent, privateExponent, p, q, dP, dQ, qInv);
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(akp);
            return Base64.ToBase64String(privateKeyInfo.ParsePrivateKey().GetEncoded());
        }

        /// <summary>    
        /// RSA私钥格式转换
        /// </summary>    
        /// <returns></returns>   
        public static string GetPrivateKeyXml(string privateKey)
        {
            var akp = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            return
                $"<RSAKeyValue><Modulus>{Base64.ToBase64String(akp.Modulus.ToByteArrayUnsigned())}</Modulus><Exponent>{Base64.ToBase64String(akp.PublicExponent.ToByteArrayUnsigned())}</Exponent><P>{Base64.ToBase64String(akp.P.ToByteArrayUnsigned())}</P><Q>{Base64.ToBase64String(akp.Q.ToByteArrayUnsigned())}</Q><DP>{Base64.ToBase64String(akp.DP.ToByteArrayUnsigned())}</DP><DQ>{Base64.ToBase64String(akp.DQ.ToByteArrayUnsigned())}</DQ><InverseQ>{Base64.ToBase64String(akp.QInv.ToByteArrayUnsigned())}</InverseQ><D>{Base64.ToBase64String(akp.Exponent.ToByteArrayUnsigned())}</D></RSAKeyValue>";
        }

        /// <summary>    
        /// RSA公钥格式转换
        /// </summary>    
        /// <returns></returns>    
        public static string GetPublicKeyXml(string publicKey)
        {
            var publicParameter = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
            return
                $"<RSAKeyValue><Modulus>{Base64.ToBase64String(publicParameter.Modulus.ToByteArrayUnsigned())}</Modulus><Exponent>{Base64.ToBase64String(publicParameter.Exponent.ToByteArrayUnsigned())}</Exponent></RSAKeyValue>";
        }

        /// <summary>    
        /// RSA公钥格式转换
        /// </summary>    
        /// <returns></returns>   
        public static string GetPublicKeyFromXml(string publicKey)
        {
            var doc = new XmlDocument();
            doc.LoadXml(publicKey);
            var modules = new BigInteger(1, Base64.Decode(doc.DocumentElement.GetElementsByTagName("Modulus")[0].InnerText));
            var exponent = new BigInteger(1, Base64.Decode(doc.DocumentElement.GetElementsByTagName("Exponent")[0].InnerText));
            var pub = new RsaKeyParameters(false, modules, exponent);
            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub);
            return Base64.ToBase64String(publicKeyInfo.ToAsn1Object().GetDerEncoded());
        }
    }
}
