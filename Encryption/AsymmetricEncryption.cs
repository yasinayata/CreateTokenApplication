using Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Encryption
{
    public static class AsymmetricEncryption
    {
        #region StringToByte
        public static byte[] StringToByte(string Data)
        {
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            return ByteConverter.GetBytes(Data);
        }
        #endregion

        #region RSA with private and public key
        #region CreateRSAPrivateKey
        public static OperationResult CreateRSAPrivateKey()
        {
            OperationResult opr = new OperationResult();
            try
            {
                //lets take a new CSP with a new 2048 bit rsa key pair
                RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);

                //how to get the private key
                RSAParameters privateKey = csp.ExportParameters(true);

                string privateKeyString;
                {
                    //we need some buffer
                    var sw = new StringWriter();
                    //we need a serializer
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    //serialize the key into the stream
                    xs.Serialize(sw, privateKey);
                    //get the string from the stream
                    privateKeyString = sw.ToString();

                    opr.Message = privateKeyString;
                }
            }
            catch (Exception exception)
            {
                opr.Result = false;
                opr.Message = exception.Message;
            }

            return opr;
        }
        #endregion

        #region CreateRSAPublicKey
        public static OperationResult CreateRSAPublicKey()
        {
            OperationResult opr = new OperationResult();
            try
            {
                //lets take a new CSP with a new 2048 bit rsa key pair
                RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);

                //and the public key ...
                RSAParameters publicKey = csp.ExportParameters(false);
                //converting the public key into a string representation
                string publicKeyString;
                {
                    //we need some buffer
                    var sw = new StringWriter();
                    //we need a serializer
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    //serialize the key into the stream
                    xs.Serialize(sw, publicKey);
                    //get the string from the stream
                    publicKeyString = sw.ToString();

                    opr.Message = publicKeyString;
                }
            }
            catch (Exception exception)
            {
                opr.Result = false;
                opr.Message = exception.Message;
            }

            return opr;
        }
        #endregion
        #endregion

        #region RSAEncrypted
        public static OperationResult<RSAParameters> RSAEncrypted(string Data)      //RSA encrypted process
        {
            OperationResult<RSAParameters> opr = new OperationResult<RSAParameters>();
            try
            {
                if (String.IsNullOrEmpty(Data))
                {
                    opr.Result = false;
                    opr.Message = Data;
                }
                else
                {
                    byte[] bytesData = StringToByte(Data);
                    RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
                    opr.Data = csp.ExportParameters(true);
                    byte[] arrayResult = csp.Encrypt(bytesData, false);
                    opr.Message = Convert.ToBase64String(arrayResult);
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

        #region RSADecrypted
        public static OperationResult<RSAParameters> RSADecrypted(string Data, RSAParameters parameters)
        {
            OperationResult<RSAParameters> opr = new OperationResult<RSAParameters>();
            try
            {
                if (String.IsNullOrEmpty(Data))
                {
                    opr.Result = false;
                    opr.Message = Data;
                }
                else
                {
                    RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
                    byte[] arrayData = Convert.FromBase64String(Data);
                    UnicodeEncoding UE = new UnicodeEncoding();
                    csp.ImportParameters(parameters);
                    byte[] arrayResult = csp.Decrypt(arrayData, false);
                    opr.Message = UE.GetString(arrayResult);
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

        #region RSAEncryptedWithPublicKey
        public static OperationResult RSAEncryptedWithPublicKey(string Data, string publicKeyString)
        {
            OperationResult opr = new OperationResult();

            try
            {
                //get a stream from the string
                var sr = new StringReader(publicKeyString);

                //we need a deserializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));

                //get the object back from the stream
                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
                csp.ImportParameters((RSAParameters)xs.Deserialize(sr));
                byte[] bytesPlainTextData = StringToByte(Data); //File.ReadAllBytes(filePath);

                //apply pkcs#1.5 padding and encrypt our data 
                var bytesCipherText = csp.Encrypt(bytesPlainTextData, false);
                //we might want a string representation of our cypher text... base64 will do
                string encryptedText = Convert.ToBase64String(bytesCipherText);
                opr.Message = encryptedText;

            }
            catch (Exception exception)
            {
                opr.Result = false;
                opr.Message = exception.Message;
            }
            return opr;
        }
        #endregion

        #region RSADecryptedWithPrivateKey
        public static OperationResult RSADecryptedWithPrivateKey(string Data, string privateKeyString)
        {
            OperationResult opr = new OperationResult();

            try
            {
                //we want to decrypt, therefore we need a csp and load our private key
                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();

                var sr = new StringReader(privateKeyString);
                //we need a deserializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //get the object back from the stream
                RSAParameters privateKey = (RSAParameters)xs.Deserialize(sr);
                csp.ImportParameters(privateKey);

                string encryptedText = Data;
                //using (StreamReader reader = new StreamReader(filePath)) { encryptedText = reader.ReadToEnd(); }
                byte[] bytesCipherText = Convert.FromBase64String(encryptedText);

                //decrypt and strip pkcs#1.5 padding
                byte[] bytesPlainTextData = csp.Decrypt(bytesCipherText, false);

                //get our original plainText back....
                UnicodeEncoding UE = new UnicodeEncoding();
                opr.Message = UE.GetString(bytesPlainTextData);
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
    }
}
