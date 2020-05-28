using System;
using System.Collections.Generic;
using System.Text;

namespace ICH.BouncyCastle
{
    public class CipherAlgorithms
    {
        public const string AES_CBC_NoPadding = "AES/CBC/NoPadding";
        public const string AES_CBC_PKCS7Padding = "AES/CBC/PKCS7Padding";
        public const string AES_CBC_ZerosPadding = "AES/CBC/ZerosPadding";
        public const string AES_CBC_ANSIX923Padding = "AES/CBC/ANSIX923Padding";
        public const string AES_CBC_ISO10126Padding = "AES/CBC/ISO10126Padding";

        public const string AES_ECB_NoPadding = "AES/ECB/NoPadding";
        public const string AES_ECB_PKCS7Padding = "AES/ECB/PKCS7Padding";
        public const string AES_ECB_ZerosPadding = "AES/ECB/ZerosPadding";
        public const string AES_ECB_ANSIX923Padding = "AES/ECB/ANSIX923Padding";
        public const string AES_ECB_ISO10126Padding = "AES/ECB/ISO10126Padding";

        public const string AES_OFB_NoPadding = "AES/OFB/NoPadding";
        public const string AES_OFB_PKCS7Padding = "AES/OFB/PKCS7Padding";
        public const string AES_OFB_ZerosPadding = "AES/OFB/ZerosPadding";
        public const string AES_OFB_ANSIX923Padding = "AES/OFB/ANSIX923Padding";
        public const string AES_OFB_ISO10126Padding = "AES/OFB/ISO10126Padding";

        public const string AES_CFB_NoPadding = "AES/CFB/NoPadding";
        public const string AES_CFB_PKCS7Padding = "AES/CFB/PKCS7Padding";
        public const string AES_CFB_ZerosPadding = "AES/CFB/ZerosPadding";
        public const string AES_CFB_ANSIX923Padding = "AES/CFB/ANSIX923Padding";
        public const string AES_CFB_ISO10126Padding = "AES/CFB/ISO10126Padding";

        public const string AES_CTS_NoPadding = "AES/CTS/NoPadding";
        public const string AES_CTS_PKCS7Padding = "AES/CTS/PKCS7Padding";
        public const string AES_CTS_ZerosPadding = "AES/CTS/ZerosPadding";
        public const string AES_CTS_ANSIX923Padding = "AES/CTS/ANSIX923Padding";
        public const string AES_CTS_ISO10126Padding = "AES/CTS/ISO10126Padding";

        public const string AES_CTR_NoPadding = "AES/CTR/NoPadding";
        public const string AES_CTR_PKCS7Padding = "AES/CTR/PKCS7Padding";
        public const string AES_CTR_ZerosPadding = "AES/CTR/ZerosPadding";
        public const string AES_CTR_ANSIX923Padding = "AES/CTR/ANSIX923Padding";
        public const string AES_CTR_ISO10126Padding = "AES/CTR/ISO10126Padding";

        public const string DES_CBC_NoPadding = "DES/CBC/NoPadding";
        public const string DES_CBC_PKCS5Padding = "DES/CBC/PKCS5Padding";
        public const string DES_CBC_ISO10126Padding = "DES/CBC/ISO10126Padding";
        public const string DES_CBC_ISO7816_4Padding = "DES/CBC/ISO7816-4Padding";
        public const string DES_CBC_X923Padding = "DES/CBC/X9.23Padding";
        public const string DES_CBC_ZeroBytePadding="DES/CBC/ZeroBytePadding";
        public const string DES_CTS_NoPadding="DES/CTS/NoPadding";
        public const string DES_CBC_WithCTS="DES/CBC/WithCTS";
        public const string DES_OFB_NoPadding="DES/OFB/NoPadding";
        public const string DES_OFB8_NoPadding= "DES/OFB8/NoPadding";
        public const string DES_CFB_NoPadding="DES/CFB/NoPadding";
        public const string DES_CFB8_NoPadding="DES/CFB8/NoPadding";
        public const string DES_CTR_NoPadding = "DES/CTR/NoPadding";
        public const string DES_EAX_NoPadding="DES/EAX/NoPadding";
        public const string DES_ECB_TBCPadding="DES/ECB/TBCPadding";
        public const string DES_CBC_TBCPadding="DES/CBC/TBCPadding";
        public const string DES_OFB64_NoPadding="DES/OFB64/NoPadding";
        public const string DES_CFB64_NoPadding="DES/CFB64/NoPadding";


        public const string DESede_CBC_WithCTS= "DESede/CBC/WithCTS";
        public const string DESede_CTS_NoPadding="DESede/CTS/NoPadding";
        public const string DESede_CBC_NoPadding = "DESede/CBC/NoPadding";
        public const string DESede_CBC_PKCS7Padding = "DESede/CBC/PKCS7Padding";
        public const string DESede_OFB_NoPadding="DESede/OFB/NoPadding";
        public const string DESede_OFB8_NoPadding= "DESede/OFB8/NoPadding";
        public const string DESede_CFB_NoPadding="DESede/CFB/NoPadding";
        public const string DESede_CFB8_NoPadding="DESede/CFB8/NoPadding";
        public const string DESede_CTR_NoPadding="DESede/CTR/NoPadding";
        public const string DESede_EAX_NoPadding="DESede/EAX/NoPadding";

        public static string SM4_ECB_PKCS7Padding = "SM4/ECB/PKCS7Padding";
        public static string SM4_ECB_NoPadding = "SM4/ECB/NoPadding";
        public static string SM4_CBC_PKCS7Padding = "SM4/CBC/PKCS7Padding";
        public static string SM4_CBC_NoPadding = "SM4/CBC/NoPadding";

        public const string RSA_NONE_NoPadding = "RSA/NONE/NoPadding";
        public const string RSA_NONE_PKCS1Padding = "RSA/NONE/PKCS1Padding";
        public const string RSA_NONE_OAEPPadding = "RSA/NONE/OAEPPadding";
        public const string RSA_NONE_OAEPWithSHA1AndMGF1Padding = "RSA/NONE/OAEPWithSHA1AndMGF1Padding";
        public const string RSA_NONE_OAEPWithSHA224AndMGF1Padding = "RSA/NONE/OAEPWithSHA224AndMGF1Padding";
        public const string RSA_NONE_OAEPWithSHA256AndMGF1Padding = "RSA/NONE/OAEPWithSHA256AndMGF1Padding";
        public const string RSA_NONE_OAEPWithSHA384AndMGF1Padding = "RSA/NONE/OAEPWithSHA384AndMGF1Padding";
        public const string RSA_NONE_OAEPWithMD5AndMGF1Padding = "RSA/NONE/OAEPWithMD5AndMGF1Padding";

        public const string RSA_ECB_NoPadding = "RSA/ECB/NoPadding";
        public const string RSA_ECB_PKCS1Padding = "RSA/ECB/PKCS1Padding";
        public const string RSA_ECB_OAEPPadding = "RSA/ECB/OAEPPadding";
        public const string RSA_ECB_OAEPWithSHA1AndMGF1Padding = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
        public const string RSA_ECB_OAEPWithSHA224AndMGF1Padding = "RSA/ECB/OAEPWithSHA224AndMGF1Padding";
        public const string RSA_ECB_OAEPWithSHA256AndMGF1Padding = "RSA/ECB/OAEPWithSHA256AndMGF1Padding";
        public const string RSA_ECB_OAEPWithSHA384AndMGF1Padding = "RSA/ECB/OAEPWithSHA384AndMGF1Padding";
        public const string RSA_ECB_OAEPWithMD5AndMGF1Padding = "RSA/ECB/OAEPWithMD5AndMGF1Padding";

    }
}
