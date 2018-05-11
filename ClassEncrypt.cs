using System;
using System.Data;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Collections;
using System.Security.Cryptography;
using System.ComponentModel;
using System.Drawing;
using System.Xml; //Чтение XML из строки

//Криптография
using Org.BouncyCastle.Crypto;

using Org.BouncyCastle.OpenSsl; //PemReader
using Org.BouncyCastle.Crypto.Encodings; //Pkcs1Encoding
using Org.BouncyCastle.Crypto.Engines; //RsaEngine
namespace NSClassText
{

    public class RSA
    {
        public class PEM
        {
            /// <summary>
            /// Расшифровка строки по СЕКРЕТНОМУ ключу.
            /// </summary>
            /// <param name="EcnryptData">Зашифрованная инфа</param>
            /// /// <param name="PrivateKeyPEM">Приватный ключ (.pem), расширение не указывать</param>
            /// <returns></returns>
            public static string Decrypt(string EcnryptData,string PrivateKeyPEM)
            {
                string SD = System.IO.Path.GetPathRoot(Environment.SystemDirectory) + @"ProgramData\MyProg\";
                if (System.IO.Directory.Exists(SD) == false) System.IO.Directory.CreateDirectory(SD);

                var bytesToDecrypt = Convert.FromBase64String(EcnryptData); // string to decrypt, base64 encoded

                AsymmetricCipherKeyPair keyPair;

                using (var reader = File.OpenText(SD+ PrivateKeyPEM + @".pem")) // file containing RSA PKCS1 private key
                    keyPair = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();

                var decryptEngine = new Pkcs1Encoding(new RsaEngine());
                decryptEngine.Init(false, keyPair.Private);

                var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
                return decrypted;
            }


            public static string RsaEncryptWithPublic(string clearText, string PublicKeyPEM)
            {
                string SD = System.IO.Path.GetPathRoot(Environment.SystemDirectory) + @"ProgramData\MyProg\";
                if (System.IO.Directory.Exists(SD) == false) System.IO.Directory.CreateDirectory(SD);

                var bytesToEncrypt = Encoding.Default.GetBytes(clearText);

                var encryptEngine = new Pkcs1Encoding(new RsaEngine());

                using (var reader = File.OpenText(SD + PublicKeyPEM + @".pem")) // file containing RSA PKCS1 Public key
                {
                    var keyParameter = (AsymmetricKeyParameter)new PemReader(reader).ReadObject();
                    encryptEngine.Init(true, keyParameter);
                }
                /*
                using (var txtreader = new StringReader(publicKey))
                {
                    var keyParameter = (AsymmetricKeyParameter)new PemReader(txtreader).ReadObject();

                    encryptEngine.Init(true, keyParameter);
                }
                */
                var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
                return encrypted;

            }

            public static string RsaEncryptWithPrivate(string clearText, string PrivateKeyPEM)
            {
                string SD = System.IO.Path.GetPathRoot(Environment.SystemDirectory) + @"ProgramData\RGSIK\";
                if (System.IO.Directory.Exists(SD) == false) System.IO.Directory.CreateDirectory(SD);

                var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);

                var encryptEngine = new Pkcs1Encoding(new RsaEngine());

                using (var reader = File.OpenText(SD + PrivateKeyPEM + @".pem")) // file containing RSA PKCS1 Public key
                {
                    var keyPair = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();
                    encryptEngine.Init(true, keyPair.Public);
                }

                /*
                using (var txtreader = new StringReader(privateKey))
                {
                    var keyPair = (AsymmetricCipherKeyPair)new PemReader(txtreader).ReadObject();

                    encryptEngine.Init(true, keyPair.Public);
                }
                */
                var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
                return encrypted;
            }


        }

    }
}
