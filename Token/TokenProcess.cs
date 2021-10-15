using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Models;
using System.IO;
using System.Linq;

namespace Token
{
    public static class TokenProcess
    {
        //************************************ TOKEN variables... **********************************
        #region TOKEN variables...
        private static byte[] rgbKey = { };
        private static byte[] rgbIV = { 2, 4, 7, 11, 19, 25, 36, 46 };
        private static string StringKey = "KVKK2021";
        #endregion

        //************************************ EncodeToken **********************************
        #region GetEncodeCertification
        public static OperationResult EncodeToken(string ClearText, DateTime ExpirationDateTime)
        {
            OperationResult operation = new OperationResult();

            try
            {
                rgbKey = Encoding.UTF8.GetBytes(StringKey.Substring(0, 8));

                DESCryptoServiceProvider des = new DESCryptoServiceProvider();
                Byte[] byteArray = Encoding.UTF8.GetBytes(ClearText);

                MemoryStream memoryStream = new MemoryStream();
                CryptoStream cryptoStream = new CryptoStream(memoryStream, des.CreateEncryptor(rgbKey, rgbIV), CryptoStreamMode.Write);

                cryptoStream.Write(byteArray, 0, byteArray.Length);
                cryptoStream.FlushFinalBlock();

                ClearText = Convert.ToBase64String(memoryStream.ToArray());

                byte[] time = BitConverter.GetBytes(ExpirationDateTime.ToBinary());
                rgbKey = System.Text.Encoding.ASCII.GetBytes(ClearText);
                ClearText = Convert.ToBase64String(time.Concat(rgbKey).ToArray());

                operation.Message = ClearText;
            }
            catch (Exception ex)
            {
                operation.Result = false;
                operation.Message = ex.ToString();
            }

            return operation;
        }
        #endregion

        //************************************ DecodeToken **********************************
        #region GetDecodeCertification
        public static OperationResult DecodeToken(string EncryptedText)
        {
            OperationResult operation = new OperationResult();

            try
            {
                byte[] data = Convert.FromBase64String(EncryptedText);
                EncryptedText = Encoding.ASCII.GetString(data, 8, data.Length - 8);
                EncryptedText = EncryptedText.Trim();

                DateTime when = DateTime.FromBinary(BitConverter.ToInt64(data, 0));
                if (when < DateTime.Now)
                {
                    operation.Result = false;
                    operation.Message = "Token has expired";
                    return operation;
                }

                rgbKey = Encoding.UTF8.GetBytes(StringKey.Substring(0, 8));
                DESCryptoServiceProvider des = new DESCryptoServiceProvider();
                Byte[] byteArray = Convert.FromBase64String(EncryptedText);
                MemoryStream memoryStream = new MemoryStream();
                CryptoStream cryptoStream = new CryptoStream(memoryStream, des.CreateDecryptor(rgbKey, rgbIV), CryptoStreamMode.Write);

                cryptoStream.Write(byteArray, 0, byteArray.Length);
                cryptoStream.FlushFinalBlock();

                EncryptedText = Encoding.UTF8.GetString(memoryStream.ToArray());

                operation.Message = EncryptedText;
            }
            catch (Exception)
            {
                operation.Result = false;
                operation.Message = "Invalid token";
            }
            return operation;
        }
        #endregion
    }
}
