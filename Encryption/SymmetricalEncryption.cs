using Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Encryption
{
    #region SymmetricalEncryption
    public static class SymmetricalEncryption
    {
        #region Variables
        internal static byte[] rgbKey = { 1, 2, 3, 4, 5, 5, 7, 8 };
        internal static byte[] rgbIV = { 10, 20, 30, 40, 40, 30, 20, 10 };
        internal static string StringKey = "1q2w3e4r";
        #endregion

        #region Byte8
        public static byte[] Byte8(string Data)
        {
            char[] arrayChar = Data.ToCharArray();
            byte[] arrayByte = new byte[arrayChar.Length];
            for (int i = 0; i < arrayByte.Length; i++)
            {
                arrayByte[i] = Convert.ToByte(arrayChar[i]);
            }
            return arrayByte;
        }
        #endregion       

        #region DES
        #region DESEncrypted
        public static OperationResult DESEncrypted(string Data)      //RSA encrypted process
        {
            OperationResult opr = new OperationResult();
            try
            {
                if (String.IsNullOrEmpty(Data))
                {
                    opr.Result = false;
                    opr.Message = Data;
                }
                else
                {
                    DESCryptoServiceProvider csp = new DESCryptoServiceProvider();
                    MemoryStream ms = new MemoryStream();
                    CryptoStream cs = new CryptoStream(ms, csp.CreateEncryptor(rgbKey, rgbIV), CryptoStreamMode.Write);
                    StreamWriter writer = new StreamWriter(cs);

                    writer.Write(Data);
                    writer.Flush();
                    cs.FlushFinalBlock();
                    writer.Flush();
                    opr.Message = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length);

                    writer.Dispose();
                    cs.Dispose();
                    ms.Dispose();
                }

            }
            catch (Exception exception)
            {
                opr.Result = false;
                opr.Message = exception.Message.ToString();
            }
            return opr;
        }
        #endregion

        #region DESDecrypted
        public static OperationResult DESDecrypted(string Data)
        {
            OperationResult opr = new OperationResult();
            try
            {
                if (String.IsNullOrEmpty(Data))
                {
                    opr.Result = false;
                    opr.Message = Data;
                }
                else
                {
                    DESCryptoServiceProvider csp = new DESCryptoServiceProvider();
                    MemoryStream ms = new MemoryStream(Convert.FromBase64String(Data));
                    CryptoStream cs = new CryptoStream(ms, csp.CreateDecryptor(rgbKey, rgbIV), CryptoStreamMode.Read);
                    StreamReader reader = new StreamReader(cs);

                    opr.Message = reader.ReadToEnd();
                    reader.Dispose();
                    cs.Dispose();
                    ms.Dispose();
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine($"Exception : {exception.Message}");
                opr.Result = false;
                opr.Message = Data;
            }
            return opr;
        }
        #endregion
        #endregion

        #region DES LimitedTime
        #region DESEncryptedLimitedTime
        public static OperationResult DESEncryptedLimitedTime(string Data, DateTime ExpirationDateTime)      //RSA encrypted process
        {
            OperationResult opr = new OperationResult();
            try
            {
                if (String.IsNullOrEmpty(Data))
                {
                    opr.Result = false;
                    opr.Message = Data;
                }
                else
                {
                    rgbKey = Encoding.UTF8.GetBytes(StringKey.Substring(0, 8));

                    Byte[] arrayData = Encoding.UTF8.GetBytes(Data);

                    DESCryptoServiceProvider csp = new DESCryptoServiceProvider();
                    MemoryStream ms = new MemoryStream();
                    CryptoStream cs = new CryptoStream(ms, csp.CreateEncryptor(rgbKey, rgbIV), CryptoStreamMode.Write);
                    StreamWriter writer = new StreamWriter(cs);

                    writer.Write(Data);
                    writer.Flush();
                    cs.FlushFinalBlock();
                    writer.Flush();

                    string EncryptedText = Convert.ToBase64String(ms.ToArray());
                    byte[] time = BitConverter.GetBytes(ExpirationDateTime.ToBinary());
                    rgbKey = System.Text.Encoding.ASCII.GetBytes(EncryptedText);
                    EncryptedText = Convert.ToBase64String(time.Concat(rgbKey).ToArray());

                    opr.Message = EncryptedText;

                    writer.Dispose();
                    cs.Dispose();
                    ms.Dispose();
                }

            }
            catch (Exception exception)
            {
                opr.Result = false;
                opr.Message = exception.Message.ToString();
            }
            return opr;
        }
        #endregion

        #region DESDecryptedLimitedTime
        public static OperationResult DESDecryptedLimitedTime(string Data)
        {
            OperationResult opr = new OperationResult();
            try
            {
                if (String.IsNullOrEmpty(Data))
                {
                    opr.Result = false;
                    opr.Message = Data;
                }
                else
                {
                    byte[] arrayData = Convert.FromBase64String(Data);
                    string EncryptedText = Encoding.ASCII.GetString(arrayData, 8, arrayData.Length - 8);
                    EncryptedText = EncryptedText.Trim();

                    DateTime when = DateTime.FromBinary(BitConverter.ToInt64(arrayData, 0));
                    if (when < DateTime.Now)
                    {
                        opr.Result = false;
                        opr.Message = "Token has expired";
                        return opr;
                    }

                    rgbKey = Encoding.UTF8.GetBytes(StringKey.Substring(0, 8));

                    DESCryptoServiceProvider csp = new DESCryptoServiceProvider();
                    MemoryStream ms = new MemoryStream(Convert.FromBase64String(EncryptedText));
                    CryptoStream cs = new CryptoStream(ms, csp.CreateDecryptor(rgbKey, rgbIV), CryptoStreamMode.Read);
                    StreamReader reader = new StreamReader(cs);

                    opr.Message = reader.ReadToEnd();
                    reader.Dispose();
                    cs.Dispose();
                    ms.Dispose();
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine($"Exception : {exception.Message}");
                opr.Result = false;
                opr.Message = "Invalid token";
            }
            return opr;
        }
        #endregion
        #endregion

        #region TripleDES 
        #region TripleDESEncrypted
        public static OperationResult TripleDESEncrypted(string Data)      //RSA encrypted process
        {
            OperationResult opr = new OperationResult();
            try
            {
                if (String.IsNullOrEmpty(Data))
                {
                    opr.Result = false;
                    opr.Message = Data;
                }
                else
                {
                    TripleDESCryptoServiceProvider csp = new TripleDESCryptoServiceProvider();
                    MemoryStream ms = new MemoryStream();
                    CryptoStream cs = new CryptoStream(ms, csp.CreateEncryptor(rgbKey, rgbIV), CryptoStreamMode.Write);
                    StreamWriter writer = new StreamWriter(cs);

                    writer.Write(Data);
                    writer.Flush();
                    cs.FlushFinalBlock();
                    writer.Flush();
                    opr.Message = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length);

                    writer.Dispose();
                    cs.Dispose();
                    ms.Dispose();
                }

            }
            catch (Exception exception)
            {
                opr.Result = false;
                opr.Message = exception.Message.ToString();
            }
            return opr;
        }
        #endregion

        #region TripleDESDecrypted
        public static OperationResult TripleDESDecrypted(string Data)
        {
            OperationResult opr = new OperationResult();
            try
            {
                if (String.IsNullOrEmpty(Data))
                {
                    opr.Result = false;
                    opr.Message = Data;
                }
                else
                {
                    TripleDESCryptoServiceProvider csp = new TripleDESCryptoServiceProvider();
                    MemoryStream ms = new MemoryStream(Convert.FromBase64String(Data));
                    CryptoStream cs = new CryptoStream(ms, csp.CreateDecryptor(rgbKey, rgbIV), CryptoStreamMode.Read);
                    StreamReader reader = new StreamReader(cs);

                    opr.Message = reader.ReadToEnd();
                    reader.Dispose();
                    cs.Dispose();
                    ms.Dispose();
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine($"Exception : {exception.Message}");
                opr.Result = false;
                opr.Message = Data;
            }
            return opr;
        }
        #endregion
        #endregion

        #region Rijndael
        #region RijndaelEncrypted
        public static OperationResult RijndaelEncrypted(string Data)      //RSA encrypted process
        {
            OperationResult opr = new OperationResult();
            try
            {
                if (String.IsNullOrEmpty(Data))
                {
                    opr.Result = false;
                    opr.Message = Data;
                }
                else
                {
                    RijndaelManaged dec = new RijndaelManaged { Mode = CipherMode.CBC };
                    MemoryStream ms = new MemoryStream();
                    CryptoStream cs = new CryptoStream(ms, dec.CreateEncryptor(rgbKey, rgbIV), CryptoStreamMode.Write);
                    StreamWriter writer = new StreamWriter(cs);

                    writer.Write(Data);
                    writer.Flush();
                    cs.FlushFinalBlock();
                    writer.Flush();
                    opr.Message = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length);
                    writer.Dispose();
                    cs.Dispose();
                }

            }
            catch (Exception exception)
            {
                opr.Result = false;
                opr.Message = exception.Message.ToString();
            }
            return opr;
        }
        #endregion

        #region RijndaelDecrypted
        public static OperationResult RijndaelDecrypted(string Data)
        {
            OperationResult opr = new OperationResult();
            try
            {
                if (String.IsNullOrEmpty(Data))
                {
                    opr.Result = false;
                    opr.Message = Data;
                }
                else
                {
                    RijndaelManaged cp = new RijndaelManaged();
                    MemoryStream ms = new MemoryStream(Convert.FromBase64String(Data));
                    CryptoStream cs = new CryptoStream(ms, cp.CreateDecryptor(rgbKey, rgbIV), CryptoStreamMode.Read);
                    StreamReader reader = new StreamReader(cs);

                    opr.Message = reader.ReadToEnd();
                    reader.Dispose();
                    cs.Dispose();
                    ms.Dispose();
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine($"Exception : {exception.Message}");
                opr.Result = false;
                opr.Message = Data;
            }
            return opr;
        }
        #endregion
        #endregion
    }
    #endregion
}
