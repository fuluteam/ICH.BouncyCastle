using System;
using System.IO;
using System.Reflection.Metadata;
using System.Text;
using ICH.BouncyCastle;
using ICH.BouncyCastle.DSA;
using Org.BouncyCastle.Utilities.Encoders;
using RSA = ICH.BouncyCastle.RSA;

namespace ICH.Security.ConsoleApp
{
    class Program
    {
        #region pkcs8_1024_private_key
        const string pkcs8_1024_private_key =
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALg3gO/xSW3fEioz1I/C5r9yyIbKsiczelJd7/4CJY10ODPghtMOX5QMWFf5/4iRj3qOoX9gtc3MVHluz1mcquE1mXUxN+3nOuS4v4okN25OxIrGSdBIT30bqYvt70D83SASDwSmVVyFziam+8Ay15XnqX0a5pRgNmAQvIr7fuxjAgMBAAECgYEAje7FuxkO2EZsunNgrLsgChWoBqKZjLaO4nNZ+z0wLcKDowS1HFwQrAKu9mm5xkFQaL8IExoyOTPbSgxkWcjppnhj8+1O1PF8fJS5r6eTH4RRMDs/Hx26a/U3DX8NsKhm5glkV1b/Mwt879RS6CThF0ESEaA6cgXuibGwx1kBBRECQQDe1aiQWHII/oRsJrfWds/kkbIutKStbY2xhzSccjIB7TH2PfSHI+cv4Lylf4qe/S7og4h3fwjL9//iL/F7xFP1AkEA06JypsKns3BFe77qNP9HAJa9o2YcDm2aSFKnWfMBoChdue9gmEUhHvg8mnsuy4t+W6WpwRVXJ4Bbfv8DFgJf9wJBAM/CJwJF5DRskKyBQN/NMLFsAdQ4Cl3ECdreM3g1pFhVfUKXqxggqljiUSCAlI79gbG5iQ/Yuivp0oJhruV1O80CQFL9zUAf7Wush1LzlxyZTtqoQk2laTMvP+VEpGPdq7GGotqbSKHt2gMvDXT3AW7IkRCXcm5JVBglebvffPJQlBkCQH6UFyZNRi0TxJT5X26HIomcUqj0+vqxFmd93jjcnsTcBJUBIqsmgofOhX0cVHEmdVpmMavVWusK/V0dNQaVEOs=";
        #endregion

        #region pkcs8_1024_private_key_pem
        const string pkcs8_1024_private_key_pem = @"-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALg3gO/xSW3fEioz
1I/C5r9yyIbKsiczelJd7/4CJY10ODPghtMOX5QMWFf5/4iRj3qOoX9gtc3MVHlu
z1mcquE1mXUxN+3nOuS4v4okN25OxIrGSdBIT30bqYvt70D83SASDwSmVVyFziam
+8Ay15XnqX0a5pRgNmAQvIr7fuxjAgMBAAECgYEAje7FuxkO2EZsunNgrLsgChWo
BqKZjLaO4nNZ+z0wLcKDowS1HFwQrAKu9mm5xkFQaL8IExoyOTPbSgxkWcjppnhj
8+1O1PF8fJS5r6eTH4RRMDs/Hx26a/U3DX8NsKhm5glkV1b/Mwt879RS6CThF0ES
EaA6cgXuibGwx1kBBRECQQDe1aiQWHII/oRsJrfWds/kkbIutKStbY2xhzSccjIB
7TH2PfSHI+cv4Lylf4qe/S7og4h3fwjL9//iL/F7xFP1AkEA06JypsKns3BFe77q
NP9HAJa9o2YcDm2aSFKnWfMBoChdue9gmEUhHvg8mnsuy4t+W6WpwRVXJ4Bbfv8D
FgJf9wJBAM/CJwJF5DRskKyBQN/NMLFsAdQ4Cl3ECdreM3g1pFhVfUKXqxggqlji
USCAlI79gbG5iQ/Yuivp0oJhruV1O80CQFL9zUAf7Wush1LzlxyZTtqoQk2laTMv
P+VEpGPdq7GGotqbSKHt2gMvDXT3AW7IkRCXcm5JVBglebvffPJQlBkCQH6UFyZN
Ri0TxJT5X26HIomcUqj0+vqxFmd93jjcnsTcBJUBIqsmgofOhX0cVHEmdVpmMavV
WusK/V0dNQaVEOs=
-----END PRIVATE KEY-----";
        #endregion

        #region 1024_public_key
        private const string _1024_public_key = "";
        #endregion

        #region pkcs8_2048_private_key
        const string pkcs8_2048_private_key =
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCf+/aieFBjGaa8aCDlgGpywAtPLS3u5pQzFUWriy1NrTI2HepLLHc/VPlt2MaWvULG8742l9uKCZ97XTdKPD1sN1iwuSDH9YrbWpb1gKzsnFx/1u9UyqlEdYKrjV5GehGiOFIxh5SrFANGUP6Q3iEns1TAu9zX3ahmehXlXq919Lqd5vbefQeit4l17wAMzzNL6m0Z3mfCQq7hWoWCbKvnKb2pw/H1/dAEFOF29J3UhXVGrQhvVKE0UaeeM4nsuqVrzivNeexpFnnOYbuvejUYKhw7N0iBF40kVPd8TFjMELc1i2EVJDBS0k1GOTRvU75zG/ACGT8xmR0EsiH/PmnnAgMBAAECggEAKHCSWWM8PrCfOwS/PAQH5FWzBiKPd9IFKBx6bfBSVU4wYQmSzcnBotqh6ihfmn7gwFWggUBFmFDyZUac0UEE7bPX0WQaazEgFm6BtjD+hRjJMO9ts+s+ejWSADdN21bD2lOOQ0LYS55VbZLPpmLf0p88DzPtkQtQpAa8Pix/AbugYr58LC7ghOqEujuJtonv14JG7K3dva5zBNVsm0HkiRB5Ge9WzI2RsmZSLfoJCpVNmKXknyoLZvhUi0SdsI0Md7yViCXtEdgRIrzYxDoObM7K6vnw64Vb6E3OWigj2aRfmwhLZ2D6yBH1jGSNOSm9zb2rGPIbsDtaFyi8F28TIQKBgQD5C3dshSRZfgZNjokVGKzEXVroLNaJzbd0YT2QloNbYv+r4S8ZyC8zVHlCd1Qjf0MFHV4uD6OkAJc4Y1lib7GZpsCZy6LwfXzi8N7Fi0YzDc01aKwxT5CqHbI5CsE1Pxo7zC4Hn+YsOITTsk9zOfxvqSnPCHuAfu53xgRKjwXhaQKBgQCkc8NIidKgjC7ITSOH9Vhj9/RUguKOYKcIoM43FQpbYXDICKzREnLwYbkJCOVCqRqgp5nATZnE95aHSA/yrolS558PMuWlWrEgBETQ2fPd1d1SuKFYUngXYxT+6lmgUwJkjMEcBULtfmXdvaqeSclOvCtqtXqv24JWlFbxjUk2zwKBgQCp+CFxdwzv5wr2M6lrNIP1IKHCg5eIRVZHn3YdEBxmapKEBBPZTL6qEaUQr9BEyb4752c3mITekWijm2qNvB1B+ITKciiqaXqqiCoCOKOYhHrhUKb0oJDjCZFxTN3AMWj+FsPzgDXfSFOfB7shsRmQO6vFGMzxTbADHqofGK2ywQKBgHg0pem/1FXGIewHdpFKpPFtrQqZIUExJOcJo7JfjtJ8xxNwQ+IOujU7OSWBexLeyLflylzmXB+9WipIYl/hdD9FTt6tNW9Ie3ALrsF6jub4DG8KxeTpYx61LgOnCRxHkNguinkQ33r5iTwsByrshFko8hNt09/3c64Vf/fQblPBAoGBAJDzThBgKWZh/CoNTy1fKPUfAcbXq2RUsa2uYBrjw4nVLiulmX12ESLn3pl5z6EaplFVN7KuIkCxQABHhgsBPJRC0oD13/PYBhhm4eUgqOEjRLRcDBWWfmstf8AjrvLc01AyIi/jEN+Sb4sJxcf8/+0C459jTEPXkTlnt+/zQb1n";
        #endregion

        #region pkcs1_1024_private_key
        const string pkcs1_1024_private_key =
            "MIICXQIBAAKBgQC4N4Dv8Ult3xIqM9SPwua/csiGyrInM3pSXe/+AiWNdDgz4IbTDl+UDFhX+f+IkY96jqF/YLXNzFR5bs9ZnKrhNZl1MTft5zrkuL+KJDduTsSKxknQSE99G6mL7e9A/N0gEg8EplVchc4mpvvAMteV56l9GuaUYDZgELyK+37sYwIDAQABAoGBAI3uxbsZDthGbLpzYKy7IAoVqAaimYy2juJzWfs9MC3Cg6MEtRxcEKwCrvZpucZBUGi/CBMaMjkz20oMZFnI6aZ4Y/PtTtTxfHyUua+nkx+EUTA7Px8dumv1Nw1/DbCoZuYJZFdW/zMLfO/UUugk4RdBEhGgOnIF7omxsMdZAQURAkEA3tWokFhyCP6EbCa31nbP5JGyLrSkrW2NsYc0nHIyAe0x9j30hyPnL+C8pX+Knv0u6IOId38Iy/f/4i/xe8RT9QJBANOicqbCp7NwRXu+6jT/RwCWvaNmHA5tmkhSp1nzAaAoXbnvYJhFIR74PJp7LsuLflulqcEVVyeAW37/AxYCX/cCQQDPwicCReQ0bJCsgUDfzTCxbAHUOApdxAna3jN4NaRYVX1Cl6sYIKpY4lEggJSO/YGxuYkP2Lor6dKCYa7ldTvNAkBS/c1AH+1rrIdS85ccmU7aqEJNpWkzLz/lRKRj3auxhqLam0ih7doDLw109wFuyJEQl3JuSVQYJXm733zyUJQZAkB+lBcmTUYtE8SU+V9uhyKJnFKo9Pr6sRZnfd443J7E3ASVASKrJoKHzoV9HFRxJnVaZjGr1VrrCv1dHTUGlRDr";
        #endregion

        #region pkcs1_1024_private_key_pem
        const string pkcs1_1024_private_key_pem = @"-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC4N4Dv8Ult3xIqM9SPwua/csiGyrInM3pSXe/+AiWNdDgz4IbT
Dl+UDFhX+f+IkY96jqF/YLXNzFR5bs9ZnKrhNZl1MTft5zrkuL+KJDduTsSKxknQ
SE99G6mL7e9A/N0gEg8EplVchc4mpvvAMteV56l9GuaUYDZgELyK+37sYwIDAQAB
AoGBAI3uxbsZDthGbLpzYKy7IAoVqAaimYy2juJzWfs9MC3Cg6MEtRxcEKwCrvZp
ucZBUGi/CBMaMjkz20oMZFnI6aZ4Y/PtTtTxfHyUua+nkx+EUTA7Px8dumv1Nw1/
DbCoZuYJZFdW/zMLfO/UUugk4RdBEhGgOnIF7omxsMdZAQURAkEA3tWokFhyCP6E
bCa31nbP5JGyLrSkrW2NsYc0nHIyAe0x9j30hyPnL+C8pX+Knv0u6IOId38Iy/f/
4i/xe8RT9QJBANOicqbCp7NwRXu+6jT/RwCWvaNmHA5tmkhSp1nzAaAoXbnvYJhF
IR74PJp7LsuLflulqcEVVyeAW37/AxYCX/cCQQDPwicCReQ0bJCsgUDfzTCxbAHU
OApdxAna3jN4NaRYVX1Cl6sYIKpY4lEggJSO/YGxuYkP2Lor6dKCYa7ldTvNAkBS
/c1AH+1rrIdS85ccmU7aqEJNpWkzLz/lRKRj3auxhqLam0ih7doDLw109wFuyJEQ
l3JuSVQYJXm733zyUJQZAkB+lBcmTUYtE8SU+V9uhyKJnFKo9Pr6sRZnfd443J7E
3ASVASKrJoKHzoV9HFRxJnVaZjGr1VrrCv1dHTUGlRDr
-----END RSA PRIVATE KEY-----";
        #endregion

        #region pkcs1_2028_private_key
        const string pkcs1_2028_private_key =
            "MIIEpAIBAAKCAQEAn/v2onhQYxmmvGgg5YBqcsALTy0t7uaUMxVFq4stTa0yNh3qSyx3P1T5bdjGlr1CxvO+Npfbigmfe103Sjw9bDdYsLkgx/WK21qW9YCs7Jxcf9bvVMqpRHWCq41eRnoRojhSMYeUqxQDRlD+kN4hJ7NUwLvc192oZnoV5V6vdfS6neb23n0HoreJde8ADM8zS+ptGd5nwkKu4VqFgmyr5ym9qcPx9f3QBBThdvSd1IV1Rq0Ib1ShNFGnnjOJ7Lqla84rzXnsaRZ5zmG7r3o1GCocOzdIgReNJFT3fExYzBC3NYthFSQwUtJNRjk0b1O+cxvwAhk/MZkdBLIh/z5p5wIDAQABAoIBAChwklljPD6wnzsEvzwEB+RVswYij3fSBSgcem3wUlVOMGEJks3JwaLaoeooX5p+4MBVoIFARZhQ8mVGnNFBBO2z19FkGmsxIBZugbYw/oUYyTDvbbPrPno1kgA3TdtWw9pTjkNC2EueVW2Sz6Zi39KfPA8z7ZELUKQGvD4sfwG7oGK+fCwu4ITqhLo7ibaJ79eCRuyt3b2ucwTVbJtB5IkQeRnvVsyNkbJmUi36CQqVTZil5J8qC2b4VItEnbCNDHe8lYgl7RHYESK82MQ6DmzOyur58OuFW+hNzlooI9mkX5sIS2dg+sgR9YxkjTkpvc29qxjyG7A7WhcovBdvEyECgYEA+Qt3bIUkWX4GTY6JFRisxF1a6CzWic23dGE9kJaDW2L/q+EvGcgvM1R5QndUI39DBR1eLg+jpACXOGNZYm+xmabAmcui8H184vDexYtGMw3NNWisMU+Qqh2yOQrBNT8aO8wuB5/mLDiE07JPczn8b6kpzwh7gH7ud8YESo8F4WkCgYEApHPDSInSoIwuyE0jh/VYY/f0VILijmCnCKDONxUKW2FwyAis0RJy8GG5CQjlQqkaoKeZwE2ZxPeWh0gP8q6JUuefDzLlpVqxIARE0Nnz3dXdUrihWFJ4F2MU/upZoFMCZIzBHAVC7X5l3b2qnknJTrwrarV6r9uCVpRW8Y1JNs8CgYEAqfghcXcM7+cK9jOpazSD9SChwoOXiEVWR592HRAcZmqShAQT2Uy+qhGlEK/QRMm+O+dnN5iE3pFoo5tqjbwdQfiEynIoqml6qogqAjijmIR64VCm9KCQ4wmRcUzdwDFo/hbD84A130hTnwe7IbEZkDurxRjM8U2wAx6qHxitssECgYB4NKXpv9RVxiHsB3aRSqTxba0KmSFBMSTnCaOyX47SfMcTcEPiDro1OzklgXsS3si35cpc5lwfvVoqSGJf4XQ/RU7erTVvSHtwC67Beo7m+AxvCsXk6WMetS4DpwkcR5DYLop5EN96+Yk8LAcq7IRZKPITbdPf93OuFX/30G5TwQKBgQCQ804QYClmYfwqDU8tXyj1HwHG16tkVLGtrmAa48OJ1S4rpZl9dhEi596Zec+hGqZRVTeyriJAsUAAR4YLATyUQtKA9d/z2AYYZuHlIKjhI0S0XAwVln5rLX/AI67y3NNQMiIv4xDfkm+LCcXH/P/tAuOfY0xD15E5Z7fv80G9Zw==";
        #endregion

        #region 2048_public_key
        private const string _2048_public_key = "";
        #endregion

        static void Main(string[] args)
        {
            //RSA_KEY_Converter();
            //RSA_PEM();
            //RSA_ECB_PKCS1Padding();
            //RSA_NONE_PKCS1Padding();

            MD5_Sample();
            //SHA256_Sample();

            //HMacSha256_Sample();

            //SHA1WithDSA_Sample();

            //SHA256WithDSA_Sample();

            //SHA256WithECDSA_Sample();

            //SHA256WithRSA_Sample();

            Console.ReadLine();
        }


        private static void RSA_KEY_Converter()
        {
            // pkcs8>>pkcs1
            Console.WriteLine("pkcs8 >> pkcs1");
            Console.WriteLine(RSAKeyConverter.PrivateKeyPkcs8ToPkcs1(pkcs8_1024_private_key));
            // pkcs1>>pkcs8
            Console.WriteLine("pkcs1 >> pkcs8");
            Console.WriteLine(RSAKeyConverter.PrivateKeyPkcs1ToPkcs8(pkcs1_1024_private_key));

            // pkcs8>>pkcs1 pem
            Console.WriteLine("pkcs8 >> pkcs1 pem");
            Console.WriteLine(RSAKeyConverter.PrivateKeyPkcs8ToPkcs1(pkcs8_1024_private_key, true));

            // pkcs1>>pkcs8 pem
            Console.WriteLine("pkcs1 >> pkcs8 pem");
            Console.WriteLine(RSAKeyConverter.PrivateKeyPkcs1ToPkcs8(pkcs1_1024_private_key, true));

            // private key pkcs1 >> public key
            Console.WriteLine(" private key pkcs1 >> public key");
            Console.WriteLine(RSAKeyConverter.GetPublicKeyFromPrivateKeyPkcs1(pkcs1_1024_private_key));

            // private key pkcs8 >> public key
            Console.WriteLine(" private key pkcs8 >> public key");
            Console.WriteLine(RSAKeyConverter.GetPublicKeyFromPrivateKeyPkcs8(pkcs8_1024_private_key));

            Console.WriteLine();
        }

        private static void RSA_PEM()
        {
            Console.WriteLine(RSAPemReader.ReadPkcs1PrivateKey(pkcs1_1024_private_key_pem));

            Console.WriteLine();

            Console.WriteLine(RSAPemWriter.WritePkcs1PrivateKey(pkcs1_1024_private_key));

            Console.WriteLine();

            Console.WriteLine(RSAPemReader.ReadPkcs8PrivateKey(pkcs8_1024_private_key_pem));

            Console.WriteLine();

            Console.WriteLine(RSAPemWriter.WritePkcs8PrivateKey(pkcs8_1024_private_key));

            Console.WriteLine();
        }

        private static void RSA_ECB_PKCS1Padding()
        {
            var data = "hello rsa";

            Console.WriteLine($"加密原文：{data}");

            // rsa pkcs8 private key encrypt
            //algorithm  rsa/ecb/pkcs1padding
            var pkcs8data = RSA.EncryptToBase64(data, RSAUtilities.GetAsymmetricKeyParameterFormAsn1PrivateKey(pkcs8_1024_private_key), Algorithms.RSA_ECB_PKCS1Padding);

            Console.WriteLine("密钥格式：pkcs8，密文算法：rsa/ecb/pkcs1padding，加密结果");
            Console.WriteLine(pkcs8data);

            //rsa pkcs1 private key encrypt
            //algorithm  rsa/ecb/pkcs1padding
            var pkcs1data = RSA.EncryptToBase64(data, RSAUtilities.GetAsymmetricKeyParameterFormPrivateKey(pkcs1_1024_private_key), Algorithms.RSA_ECB_PKCS1Padding);

            Console.WriteLine($"密钥格式：pkcs1，密文算法：rsa/ecb/pkcs1padding");
            Console.WriteLine(pkcs1data);

            Console.WriteLine($"加密结果比对是否一致：{pkcs8data.Equals(pkcs1data)}");

            var _1024_public_key = RSAKeyConverter.GetPublicKeyFromPrivateKeyPkcs1(pkcs1_1024_private_key);

            Console.WriteLine($"从pkcs1私钥中提取公钥：");
            Console.WriteLine(_1024_public_key);

            Console.WriteLine("使用公钥解密数据：");
            //rsa public key decrypt
            //algorithm  rsa/ecb/pkcs1padding
            Console.WriteLine(RSA.DecryptFromBase64(pkcs1data, RSAUtilities.GetAsymmetricKeyParameterFormPublicKey(_1024_public_key), Algorithms.RSA_ECB_PKCS1Padding));

            Console.WriteLine();
        }

        private static void RSA_NONE_PKCS1Padding()
        {
            var data = "RSA_NONE_PKCS1Padding";

            //rsa pkcs1 private key encrypt
            var encryptdata1 = RSA.EncryptToBase64(data, RSAUtilities.GetAsymmetricKeyParameterFormPrivateKey(pkcs1_1024_private_key),
                Algorithms.RSA_NONE_PKCS1Padding);
            Console.WriteLine(encryptdata1);

            //rsa pkcs1 private key encrypt
            //algorithm  rsa/none/pkcs1padding
            var encryptdata2 = RSA.EncryptToBase64(data,
                RSAUtilities.GetAsymmetricKeyParameterFormAsn1PrivateKey(pkcs8_1024_private_key),
                Algorithms.RSA_NONE_PKCS1Padding);

            Console.WriteLine(encryptdata2);

            Console.WriteLine(encryptdata1.Equals(encryptdata2));

            var _1024_public_key = RSAKeyConverter.GetPublicKeyFromPrivateKeyPkcs1(pkcs1_1024_private_key);

            //rsa public key decrypt
            //algorithm  rsa/none/pkcs1padding
            Console.WriteLine(RSA.DecryptFromBase64(encryptdata2, RSAUtilities.GetAsymmetricKeyParameterFormPublicKey(_1024_public_key), Algorithms.RSA_NONE_PKCS1Padding));

            Console.WriteLine();
        }


        private static void MD5_Sample()
        {
            var s = "hello md5";
            Console.WriteLine(s);

            var resBytes1 = MD5.Compute(s);

            var resBytes2 = MD5.Compute2(s);

            var a1 = BitConverter.ToString(resBytes1).Replace("-", "");
            Console.WriteLine("通过BitConverter.ToString转换得到结果：");
            Console.WriteLine(a1);
            var a2 = Hex.ToHexString(resBytes1).ToUpper();
            Console.WriteLine("通过Hex.ToHexString转换得到结果：");
            Console.WriteLine(a2);

            var a3 = Hex.ToHexString(resBytes2).ToUpper();

            Console.WriteLine("不使用BouncyCastle得到结果：");
            Console.WriteLine(a3);

            Console.WriteLine();
        }

        private static void SHA256_Sample()
        {
            var s = "hello sha-256";
            Console.WriteLine(s);

            Console.WriteLine("使用BouncyCastle计算结果（转Base64字符串）：");
            Console.WriteLine(Base64.ToBase64String(SHA256.Compute1(s)));
            Console.WriteLine();
            Console.WriteLine("不使用BouncyCastle计算结果（转Base64字符串）：");
            Console.WriteLine(Base64.ToBase64String(SHA256.Compute2(s)));
        }

        private static void HMacSha256_Sample()
        {
            var s = "hello hmac sha256";
            Console.WriteLine(s);
            var k = HMACSHA256.GeneratorKey();
            Console.WriteLine("密钥（十六进制字符串）：");
            Console.WriteLine(Hex.ToHexString(k));
            Console.WriteLine("密钥（Base64字符串）：");
            Console.WriteLine(Base64.ToBase64String(k));
            Console.WriteLine();
            var b1 = HMACSHA256.Compute(s, k);
            Console.WriteLine("使用BouncyCastle计算结果（转Base64字符串）：");
            Console.WriteLine(Base64.ToBase64String(b1));
            Console.WriteLine("使用BouncyCastle计算结果（转十六进制字符串）：");
            Console.WriteLine(Hex.ToHexString(b1));
            Console.WriteLine();
            var b2 = HMACSHA256.Compute2(s, k);

            Console.WriteLine("不使用BouncyCastle计算结果（转Base64字符串）：");
            Console.WriteLine(Base64.ToBase64String(b2));
            Console.WriteLine("不使用BouncyCastle计算结果（转十六进制字符串）：");
            Console.WriteLine(Hex.ToHexString(b2));
        }

        private static void SHA1WithDSA_Sample()
        {
            var keyParameter = DSAKeyGenerator.Generator();

            var sign = SHA1WithDSA.GenerateSignature("hello dsa",
                   RSAUtilities.GetAsymmetricKeyParameterFormAsn1PrivateKey(keyParameter.PrivateKey));

            Console.WriteLine($"sign:{sign}");

            var verified = SHA1WithDSA.VerifySignature("hello dsa", sign,
                 RSAUtilities.GetAsymmetricKeyParameterFormPublicKey(keyParameter.PublicKey));

            Console.WriteLine(verified ? "signature verified" : "signature not verified");
        }

        private static void SHA256WithDSA_Sample()
        {
            var s = "hello dsa";
            Console.WriteLine(s);
            var keyParameter = DSAKeyGenerator.Generator();

            Console.WriteLine("私钥：");
            Console.WriteLine(keyParameter.PrivateKey);
            Console.WriteLine("公钥：");
            Console.WriteLine(keyParameter.PublicKey);

            Console.WriteLine();

            var sign = SHA256WithDSA.GenerateSignature(s,
                RSAUtilities.GetAsymmetricKeyParameterFormAsn1PrivateKey(keyParameter.PrivateKey));

            Console.WriteLine($"sign:{sign}");

            var verified = SHA256WithDSA.VerifySignature(s, sign,
                RSAUtilities.GetAsymmetricKeyParameterFormPublicKey(keyParameter.PublicKey));

            Console.WriteLine("验证结果：");
            Console.WriteLine(verified ? "signature verified" : "signature not verified");
        }

        private static void SHA256WithECDSA_Sample()
        {
            var s = "hello ec dsa";
            Console.WriteLine(s);
            var keyParameter = ECDSAKeyGenerator.Generator();

            Console.WriteLine("私钥：");
            Console.WriteLine(keyParameter.PrivateKey);
            Console.WriteLine("公钥：");
            Console.WriteLine(keyParameter.PublicKey);

            var sign = SHA256WithECDSA.GenerateSignature(s,
                RSAUtilities.GetAsymmetricKeyParameterFormAsn1PrivateKey(keyParameter.PrivateKey));

            Console.WriteLine($"sign:{sign}");

            var verified = SHA256WithECDSA.VerifySignature(s, sign,
                RSAUtilities.GetAsymmetricKeyParameterFormPublicKey(keyParameter.PublicKey));

            Console.WriteLine("验证结果：");
            Console.WriteLine(verified ? "signature verified" : "signature not verified");
        }

        private static void SHA256WithRSA_Sample()
        {
            var s = "hello sha256 with rsa";
            Console.WriteLine(s);

            var keyParameter = RSAKeyGenerator.Pkcs8(2048);

            Console.WriteLine("私钥：");
            Console.WriteLine(keyParameter.PrivateKey);
            Console.WriteLine("公钥：");
            Console.WriteLine(keyParameter.PublicKey);

            Console.WriteLine();

            Console.WriteLine("使用BouncyCastle：");

            var sign1 = SHA256WithRSA.GenerateSignature(s,
                 RSAUtilities.GetAsymmetricKeyParameterFormAsn1PrivateKey(keyParameter.PrivateKey));
            Console.WriteLine("sign1：");
            Console.WriteLine(sign1);

            var verified1 = SHA256WithRSA.VerifySignature(s, sign1,
                RSAUtilities.GetAsymmetricKeyParameterFormPublicKey(keyParameter.PublicKey));

            Console.WriteLine("验证结果：");
            Console.WriteLine(verified1 ? "signature verified" : "signature not verified");
            Console.WriteLine();

            Console.WriteLine("不使用BouncyCastle：");

            var sign2 = SHA256WithRSA.GenerateSignature(s,
                RSAUtilities.GetRsaParametersFormAsn1PrivateKey(keyParameter.PrivateKey));

            Console.WriteLine("sign2：");
            Console.WriteLine(sign2);

            var verified2 = SHA256WithRSA.VerifySignature(s, sign1,
                RSAUtilities.GetAsymmetricKeyParameterFormPublicKey(keyParameter.PublicKey));

            Console.WriteLine("验证结果：");

            Console.WriteLine(verified2 ? "signature verified" : "signature not verified");
            Console.WriteLine();
        }
    }
}
