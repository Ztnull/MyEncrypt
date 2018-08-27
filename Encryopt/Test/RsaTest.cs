
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Encryopt.Helpers;

namespace Encryopt.Test
{
    public class RsaTest
    {
        public static string GetRasString()
        {

            KeyValuePair<string, string> encryptDecrypt = RsaEncrypt.GetKeyPair();
            string rsaEn1 = RsaEncrypt.Encrypt("222222", encryptDecrypt.Key);
            return rsaEn1;
        }
    }
}
