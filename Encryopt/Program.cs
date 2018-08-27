using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Encryopt.Helpers;
using Encryopt.Test;

namespace Encryopt
{
    class Program
    {
        static void Main(string[] args)
        {
            {//MD5
             //非对称不可逆
                Console.WriteLine("*************************************非对称不可逆 MD5****************************************");
                string fileNmae = @"F:\志翔学校.rar";
                string fileNmaeCopy = @"F:\志翔学校 - 副本.rar";
                Console.WriteLine(MD5Encrypt.Encrypt("123"));
                Console.WriteLine(MD5Encrypt.Encrypt("123"));

                Console.WriteLine(MD5Encrypt.Encrypt("321null"));

                Console.WriteLine("文件MD5 Soure：" + MD5Encrypt.AbstractFile(fileNmae));
                Console.WriteLine("文件MD5 Copy：" + MD5Encrypt.AbstractFile(fileNmaeCopy));

            }

            {//DesEncrypt
                //对称可逆加密
                //速度比较快
                Console.WriteLine("*************************************对称可逆加密 DES****************************************");

                string des = DesEncrypt.Encrypt("1233211234567890");
                string res = DesEncrypt.Decrypt(des);
                Console.WriteLine("Desc：" + des);
                Console.WriteLine("ESC：" + res);
            }


            {//Ras
                //非对称可逆加密
                //速度比较慢
                Console.WriteLine("*************************************非对称可逆加密 RSA****************************************");

                KeyValuePair<string, string> encryptDecrypt = RsaEncrypt.GetKeyPair();
                string rsaEn1 = RsaEncrypt.Encrypt("222222", encryptDecrypt.Key);
                string rsaDe1 = RsaEncrypt.Decrypt(rsaEn1, encryptDecrypt.Value);
                Console.WriteLine("加密：" + rsaEn1);
                Console.WriteLine("解密：" + rsaDe1);
                Console.WriteLine("公钥："+ encryptDecrypt.Key);
                Console.WriteLine("私钥：" + encryptDecrypt.Value);

            }


            {//Ras test
                //非对称可逆加密
                //速度比较慢
                Console.WriteLine("*************************************非对称可逆加密 RSA****************************************");
                RSAUtil rsa = new RSAUtil();
                //rsa.CreateRSAKey();
                //StreamReader reader1 = new StreamReader("privatekey.xml");
                //XmlDocument document1 = new XmlDocument();
                //document1.LoadXml(reader1.ReadToEnd());
                //XmlElement element1 = (XmlElement)document1.SelectSingleNode("root");
                //parameters1.Modulus = ReadChild(element1, "Modulus");
                //var r1 = rsa.ToHexString(rsa.ReadChild(element1, "Exponent"));
                //var r2 = rsa.ToHexString(rsa.ReadChild(element1, "D"));
                //var r3 = rsa.ToHexString(rsa.ReadChild(element1, "Q"));
                //var r4 = rsa.ToHexString(rsa.ReadChild(element1, "P"));
                var en = rsa.EnCrypt("123");
                var doEn = rsa.DoEncrypt(en);

                Console.WriteLine("原文：" + doEn);
                Console.WriteLine("密文："+en);
                Console.WriteLine("解密："+doEn);
                //Console.WriteLine(r1);
                //Console.WriteLine(r2);
                //Console.WriteLine(r3);
                //Console.WriteLine(r4);
                //parameters1.DP = ReadChild(element1, "DP");
                //parameters1.DQ = ReadChild(element1, "DQ");
                //parameters1.P = ReadChild(element1, "P");
                //parameters1.Q = ReadChild(element1, "Q");
                //parameters1.InverseQ = ReadChild(element1, "InverseQ");
                //reader1.Close();

            }

            Console.ReadKey();
        }
    }
}
