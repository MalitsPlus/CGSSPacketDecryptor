/* CGSS通信加密概要
https://subdiox.github.io/deresute/user/general.html

Cryptographer
UDID および USER_ID の暗号化メソッドについて解説する。

なおこの手法は marcan/deresuteme では lolfuscate と呼ばれている。

エンコードでは文字列から以下のようにして文字列を生成する。

文字列の長さ（16進数で4桁）
各文字に対して
2桁の乱数
文字コード+10 にあたる文字
1桁の乱数
32桁の乱数
デコードでは逆に操作すればよい。

実装は Cute.Cryptographer 内の encode および decode にある。

リクエストボディの生成（CryptAES）
リクエストボディは Cute.NetworkTask 内の CreateBody に生成方法がある。

順序としては

MessagePack によりバイナリ列に変換
Base64 でエンコード
Rijndael で暗号化
最後に32文字の鍵を結合
Base64 でエンコード
となる。

MessagePack について
MessagePack は JSON に似たオブジェクトのシリアライズフォーマットである。

クライアントでは masharada/msgpack-unity を用いているようである。

サーバー側の MessagePack は古いバージョンを用いているため、str 8 フォーマットを受け付けない。一部実装では compatibility mode を使用する必要がある。

型は曖昧に実装されているようである（たとえば int 32 であるところを uint 32 で送っても問題ない）。

詳細は 仕様 を確認するとよい。

暗号化
実際には Cute.CryptAES の EncryptRJ256(string prm_text_to_encrypt) というメソッドで暗号化を行っている。

なお鍵を結合して2度目の Base64 によるエンコードもこのメソッド内で行っている。

実装には .NET の System.Security.Cryptography.RijndaelManaged を用いているが、他実装でも可能である。

条件は以下のとおりである。

ブロック暗号手法：Rijndael
暗号利用モード：CBC（Cipher Block Chaining）
ブロックサイズ：256 bit
鍵サイズ：256 bit
パディング：ゼロ埋め
鍵：適当な32文字の文字列
初期化ベクトル：UDID の - を取り除いた32文字
鍵は Base64::encode64((0...32).map{'%x' % rand(65536)}.join)[0...32] のような実装で作っている。

復号化
レスポンスの復号化は同様に行えばよい。これは Cute.NetworkManager で行われている。

Base64 でデコード
最後の32文字の鍵を取る
Rijndael で復号化（条件は暗号化時と同一）
Base64 でデコード
MessagePack を Dictionary などに展開
なお UDID が不明の通信では "\0"*32 が初期化ベクトルとなる（正規の通信ではこの現象は起こりえない）。
 */

using MessagePack;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CGSSPacketDecryptor
{
    class Cryptographer
    {
        private Cryptographer() { }

        private static Cryptographer instance;
        public static Cryptographer Get() {
            if (instance == null) {
                instance = new Cryptographer();
            }
            return instance;
        }

        public string defaultUDID = "00000000-0000-0000-0000-000000000000";

        public string DecryptData(string raw, string udid) {

            // Rijndael解密
            string decrypt = DecryptAES128(raw, udid);
            // MessagePack反序列
            string decode = MsgPackDerialize(decrypt);
            return decode;
        }

        public string EncryptData(string text, string udid) {
            // MessagePack序列
            string encode = MsgPackSerialize();
            // Rijndael加密
            string encrypt = EncryptRJ256(Encoding.UTF8.GetBytes(encode), udid);
            return encrypt;
        }

        /// <summary>
        /// 解码UDID
        /// </summary>
        /// <param name="enstr">编码后的UDID</param>
        /// <returns>正常的UDID，若出错则返回null</returns>
        public string DecodeUDID(string enstr) {
            if (enstr == null || enstr.Length < 5) {
                return defaultUDID;
            }

            string udid = string.Empty;
            try {
                int lenth = int.Parse(enstr.Substring(0, 4), System.Globalization.NumberStyles.HexNumber);
                for (int i = 4 + 2; i < enstr.Length && udid.Length < lenth; i += 4) {
                    char value = enstr[i];
                    udid += Convert.ToChar(Convert.ToInt32(value) - 10);
                }
            } catch (Exception) {
                udid = defaultUDID;
            }
            return udid;
        }

        private string MsgPackSerialize() {
            var dic = new Dictionary<string, dynamic>() {
                { "key1", "value1" },
                { "key2", "value2" }
            };
            byte[] data = MessagePackSerializer.Serialize(dic);
            string encoded = Convert.ToBase64String(data);
            return encoded;
        }

        private string MsgPackDerialize(string text) {
            byte[] data = Convert.FromBase64String(text);
            string json = MessagePackSerializer.ConvertToJson(data);
            return json;
        }

        private byte[] HexString2Bytes(string hex) {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        private string DecryptAES128(string raw, string udid) {
            byte[] iv = HexString2Bytes(udid.Replace("-", string.Empty));
            byte[] rawArray = Convert.FromBase64String(raw);

            byte[] keyArray = new byte[32];
            Array.Copy(rawArray, rawArray.Length - keyArray.Length, keyArray, 0, keyArray.Length);

            byte[] encryptedArray = new byte[rawArray.Length - keyArray.Length];
            Array.Copy(rawArray, 0, encryptedArray, 0, encryptedArray.Length);

            RijndaelManaged rijndael = new RijndaelManaged() {
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC,
                KeySize = 256,
                BlockSize = 128,
                Key = keyArray,
                IV = iv
            };

            ICryptoTransform transform = rijndael.CreateDecryptor(keyArray, iv);
            byte[] final = new byte[encryptedArray.Length];

            MemoryStream mStream = new MemoryStream(encryptedArray);
            CryptoStream cStream = new CryptoStream(mStream, transform, CryptoStreamMode.Read);
            cStream.Read(final, 0, final.Length);

            return Encoding.UTF8.GetString(final).TrimEnd(new char[1]);
        }

        private string DecryptRJ256(string raw, string udid) {
            byte[] iv = Encoding.UTF8.GetBytes(udid.Replace("-", string.Empty));
            byte[] rawArray = Convert.FromBase64String(raw);

            byte[] keyArray = new byte[32];
            Array.Copy(rawArray, rawArray.Length - keyArray.Length, keyArray, 0, keyArray.Length);

            byte[] encryptedArray = new byte[rawArray.Length - keyArray.Length];
            Array.Copy(rawArray, 0, encryptedArray, 0, encryptedArray.Length);

            RijndaelManaged rijndael = new RijndaelManaged() {
                Padding = PaddingMode.Zeros,
                Mode = CipherMode.CBC,
                KeySize = 256,
                BlockSize = 256,
                Key = keyArray,
                IV = iv
            };
            
            ICryptoTransform transform = rijndael.CreateDecryptor(keyArray, iv);
            byte[] final = new byte[encryptedArray.Length];

            MemoryStream mStream = new MemoryStream(encryptedArray);
            CryptoStream cStream = new CryptoStream(mStream, transform, CryptoStreamMode.Read);
            cStream.Read(final, 0, final.Length);

            return Encoding.UTF8.GetString(final).TrimEnd(new char[1]);
        }

        private string EncryptRJ256(byte[] textArray, string udid) {
            string keyString = GenerateKeyString();
            byte[] keyArray = Encoding.UTF8.GetBytes(keyString);
            byte[] iv = Encoding.UTF8.GetBytes(udid.Replace("-", string.Empty));

            RijndaelManaged rijndael = new RijndaelManaged() {
                Padding = PaddingMode.Zeros,
                Mode = CipherMode.CBC,
                KeySize = 256,
                BlockSize = 256,
                Key = keyArray,
                IV = iv
            };

            ICryptoTransform transform = rijndael.CreateEncryptor(keyArray, iv);
            MemoryStream mStream = new MemoryStream();
            CryptoStream cStream = new CryptoStream(mStream, transform, CryptoStreamMode.Write);

            cStream.Write(textArray, 0, textArray.Length);
            cStream.FlushFinalBlock();

            // 将key附到最后32字节
            byte[] crypted = mStream.ToArray();
            byte[] finalArray = new byte[crypted.Length + keyArray.Length];
            Array.Copy(crypted, 0, finalArray, 0, crypted.Length);
            Array.Copy(keyArray, 0, finalArray, crypted.Length, keyArray.Length);

            string finalString = Convert.ToBase64String(finalArray);
            return finalString;
        }

        private string DecryptRJ256Original(byte[] encryptedData, string udid) {
            byte[] array = encryptedData;
            RijndaelManaged expr_0C = new RijndaelManaged();
            expr_0C.Padding = PaddingMode.Zeros;
            expr_0C.Mode = CipherMode.CBC;
            expr_0C.KeySize = 256;
            expr_0C.BlockSize = 256;
            byte[] array2 = new byte[32];
            byte[] rgbIV = new byte[32];
            byte[] array3 = new byte[array.Length - array2.Length];
            Array.Copy(array, 0, array3, 0, array3.Length);
            Array.Copy(array, array.Length - array2.Length, array2, 0, array2.Length);
            rgbIV = Encoding.UTF8.GetBytes(udid.Replace("-", string.Empty));
            ICryptoTransform transform = expr_0C.CreateDecryptor(array2, rgbIV);
            byte[] array4 = new byte[array3.Length];
            new CryptoStream(new MemoryStream(array3), transform, CryptoStreamMode.Read).Read(array4, 0, array4.Length);
            return Encoding.UTF8.GetString(array4).TrimEnd(new char[1]);
        }

        private string GenerateKeyString() {
            string text = string.Empty;
            for (int i = 0; i < 32; i++) {
                text += string.Format("{0:x}", new Random().Next(0, 65535));
            }
            return Convert.ToBase64String(Encoding.ASCII.GetBytes(text.ToString())).Substring(0, 32);
        }

        private string EncodeBase64(string code) {
            string encode = "";
            byte[] bytes = Encoding.UTF8.GetBytes(code);
            try {
                encode = Convert.ToBase64String(bytes);
            } catch {
                encode = code;
            }
            return encode;
        }

        private string DecodeBase64(string code) {
            string decode = "";
            byte[] bytes = Convert.FromBase64String(code);
            try {
                decode = Encoding.UTF8.GetString(bytes);
            } catch {
                decode = code;
            }
            return decode;
        }
    }
}
