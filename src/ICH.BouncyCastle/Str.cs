using System;
using System.Collections.Generic;
using System.Text;

namespace ICH.BouncyCastle
{
    public class Str
    {
        public static string GenerateRandom(int length)
        {
            var chars = "abcdefghijklmnopqrstuvwxyz1234567890";
            var letters = new StringBuilder();
            for (var i = 0; i < length; i++)
            {
                letters.Append(chars[new Random(Guid.NewGuid().GetHashCode()).Next(chars.Length)]);
            }
            return letters.ToString();
        }
    }
}
