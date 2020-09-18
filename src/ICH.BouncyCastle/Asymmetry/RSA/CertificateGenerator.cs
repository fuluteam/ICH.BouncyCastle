using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ICH.BouncyCastle.Asymmetry.RSA
{
    public class CertificateGenerator
    {
        /// <summary>
        /// 生成X509 V3证书
        /// </summary>
        /// <param name="certPath">Cert证书路径</param>
        /// <param name="endDate">证书失效时间</param>
        /// <param name="keySize">密钥长度</param>
        /// <param name="password">证书密码</param>
        /// <param name="signatureAlgorithm">设置将用于签署此证书的签名算法</param>
        /// <param name="issuer">设置此证书颁发者的DN</param>
        /// <param name="subject">设置此证书使用者的DN</param>
        /// <param name="pfxPath">Pfx证书路径</param>
        /// <param name="friendlyName">设置证书友好名称（可选）</param>
        /// <param name="startDate">证书生效时间</param>
        /// <param name="algorithm">加密算法</param>
        public static void X509V3(string algorithm, int keySize, string password, string signatureAlgorithm,
            DateTime startDate, DateTime endDate, X509Name issuer, X509Name subject, string certPath, string pfxPath,
            string friendlyName = "")
        {
            //generate Random Numbers
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(randomGenerator);

            var keyGenerator = GeneratorUtilities.GetKeyPairGenerator(algorithm);
            keyGenerator.Init(new KeyGenerationParameters(new SecureRandom(), keySize));

            var keyPair = keyGenerator.GenerateKeyPair();

            var v3CertGen = new X509V3CertificateGenerator();
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);
            v3CertGen.SetSerialNumber(serialNumber); //设置证书的序列号

            v3CertGen.SetIssuerDN(issuer); //设置颁发者信息
            v3CertGen.SetSubjectDN(subject); //设置使用者信息

            v3CertGen.SetNotBefore(startDate); //设置证书的生效日期
            v3CertGen.SetNotAfter(endDate); //设置证书失效的日期
            v3CertGen.SetPublicKey(keyPair.Public); //设置此证书的公钥

            ISignatureFactory sigFact = new Asn1SignatureFactory(signatureAlgorithm, keyPair.Private); //签名算法&设置此证书的私钥

            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);

            //设置一些扩展字段
            //基本约束
            v3CertGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            //使用者密钥标识符
            v3CertGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(spki));
            //授权密钥标识符
            v3CertGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(spki));

            var x509Certificate = v3CertGen.Generate(sigFact); //生成证书
            x509Certificate.CheckValidity(); //检查当前日期是否在证书的有效期内
            x509Certificate.Verify(keyPair.Public); //使用公钥验证证书的签名

            var certificate2 = new X509Certificate2(DotNetUtilities.ToX509Certificate(x509Certificate))
            {
                FriendlyName = friendlyName, //设置友好名称
            };

            //cer公钥文件
            var bytes = certificate2.Export(X509ContentType.Cert);
            using (var fs = new FileStream(certPath, FileMode.Create))
            {
                fs.Write(bytes, 0, bytes.Length);
            }

            //pfx证书，包含公钥私钥
            //CopyWithPrivateKey netstandard2.1支持
            certificate2 =
                certificate2.CopyWithPrivateKey(DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)keyPair.Private));

            var bytes2 = certificate2.Export(X509ContentType.Pfx, password);
            using (var fs = new FileStream(pfxPath, FileMode.Create))
            {
                fs.Write(bytes2, 0, bytes2.Length);
            }


            var a = certificate2.GetRawCertDataString();
            var b = Hex.Encode(certificate2.RawData);
            X509Certificate2 x2 = new X509Certificate2(Hex.Decode(b), "123456");
            var c = a;
            //如果使用 netstandard2.0 请使用下面的代码
#if NETSTANDARD2_0
            var certEntry = new X509CertificateEntry(x509Certificate);
            var store = new Pkcs12StoreBuilder().Build();
            store.SetCertificateEntry(friendlyName, certEntry);   //设置证书  
            var chain = new X509CertificateEntry[1];
            chain[0] = certEntry;
            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(keyPair.Private), chain);   //设置私钥  
            using (var fs = File.Create(pfxPath))
            {
                store.Save(fs, password.ToCharArray(), new SecureRandom()); //保存  
            }
#endif

        }

        public static X509Certificate2 GenerateSelfSignedCertificate(X509Name issuer, X509Name subject, AsymmetricKeyParameter issuerPrivKey)
        {
            const int keyStrength = 2048;

            //generate random numbers
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(randomGenerator);
            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WITHRSA", issuerPrivKey, random);

            //the certificate generator
            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, true, new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth));

            //serial number
            BigInteger serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Issuer and Subject Name
            //X509Name subjectDN = new X509Name("CN=" + subjectName);
            //X509Name issuerDN = new X509Name("CN=" + issuerName);
            certificateGenerator.SetIssuerDN(issuer);
            certificateGenerator.SetSubjectDN(subject);

            //valid For
            DateTime notBefore = DateTime.Now.AddDays(-1);
            DateTime notAfter = notBefore.AddYears(2);
            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            //Subject Public Key
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            //selfSign certificate
            Org.BouncyCastle.X509.X509Certificate certificate = certificateGenerator.Generate(signatureFactory);
            //var dotNetPrivateKey = ToDotNetKey((RsaPrivateCrtKeyParameters)subjectKeyPair.Private);

            //merge into X509Certificate2

            var certificate2 = new X509Certificate2(DotNetUtilities.ToX509Certificate(certificate))
            {
                FriendlyName = "fulu sso", //设置友好名称
            };

            certificate2 = certificate2.CopyWithPrivateKey(DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)subjectKeyPair.Private));

            certificate2.FriendlyName = "fulu sso";

            var bytes2 = certificate2.Export(X509ContentType.Pfx, "123456");
            using (var fs = new FileStream("mypfx2.pfx", FileMode.Create))
            {
                fs.Write(bytes2, 0, bytes2.Length);
            }

         
            //var x509 = new X509Certificate2(DotNetUtilities.ToX509Certificate(certificate))
            //{
            //    PrivateKey = dotNetPrivateKey,
            //    FriendlyName = "fulu sso"
            //};

            return certificate2;
        }

        public static AsymmetricAlgorithm ToDotNetKey(RsaPrivateCrtKeyParameters privateKey)
        {
            var cspParams = new CspParameters()
            {
                KeyContainerName = Guid.NewGuid().ToString(),
                KeyNumber = (int)KeyNumber.Exchange,
                Flags = CspProviderFlags.UseMachineKeyStore
            };

            var rsaProvider = new RSACryptoServiceProvider(cspParams);
            var parameters = new RSAParameters()
            {
                Modulus = privateKey.Modulus.ToByteArrayUnsigned(),
                P = privateKey.P.ToByteArrayUnsigned(),
                Q = privateKey.Q.ToByteArrayUnsigned(),
                DP = privateKey.DP.ToByteArrayUnsigned(),
                DQ = privateKey.DQ.ToByteArrayUnsigned(),
                InverseQ = privateKey.QInv.ToByteArrayUnsigned(),
                D = privateKey.Exponent.ToByteArrayUnsigned(),
                Exponent = privateKey.PublicExponent.ToByteArrayUnsigned()
            };

            rsaProvider.ImportParameters(parameters);

            return rsaProvider;
        }

        private static SecureString ConvertToSecureString(string password)
        {
            if (password == null)
                throw new ArgumentNullException("password");

            var securePassword = new SecureString();

            foreach (char c in password)
                securePassword.AppendChar(c);

            securePassword.MakeReadOnly();
            return securePassword;
        }


        public static bool addCertToStore(System.Security.Cryptography.X509Certificates.X509Certificate2 cert, System.Security.Cryptography.X509Certificates.StoreName st, System.Security.Cryptography.X509Certificates.StoreLocation sl)
        {
            bool bRet = false;

            try
            {
                X509Store store = new X509Store(st, sl);
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);

                store.Close();
            }
            catch
            {

            }

            return bRet;
        }
    }
}
