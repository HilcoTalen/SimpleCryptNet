// Original C++ Copyright (c) 2011, Andre Somers.
// See also the QT info: https://wiki.qt.io/Simple_encryption_with_SimpleCrypt

namespace SimpleCryptNet
{
    using System.IO.Compression;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// The compression mode enum.
    /// </summary>
    public enum CompressionMode
    {
        /// <summary>
        /// Only apply compression if that results in a shorter plaintext.
        /// </summary>
        CompressionAuto,

        /// <summary>
        /// Always apply compression. Note that for short inputs, a compression may result in longer data
        /// </summary>
        CompressionAlways,

        /// <summary>
        /// Never apply compression.
        /// </summary>
        CompressionNever,
    }

    /// <summary>
    /// The error enum.
    /// </summary>
    public enum Error
    {
        /// <summary>
        /// No error occurred.
        /// </summary>
        ErrorNoError,

        /// <summary>
        /// No key was set. You can not encrypt or decrypt without a valid key.
        /// </summary>
        ErrorNoKeySet,

        /// <summary>
        /// The version of this data is unknown, or the data is otherwise not valid.
        /// </summary>
        ErrorUnknownVersion,

        /// <summary>
        /// The integrity check of the data failed. Perhaps the wrong key was used.
        /// </summary>
        ErrorIntegrityFailed,
    }

    /// <summary>
    /// The integrity protection mode.
    /// </summary>
    public enum IntegrityProtectionMode
    {
        /// <summary>
        /// The integerity of the encrypted data is not protected. It is not really possible to detect a wrong key, for instance.
        /// </summary>
        ProtectionNone,

        /// <summary>
        /// A simple checksum is used to verify that the data is in order. If not, an empty string is returned.
        /// </summary>
        ProtectionChecksum,

        /// <summary>
        /// A cryptographic hash is used to verify the integrity of the data. This method produces a much stronger, but longer check
        /// </summary>
        ProtectionHash,
    }

    /// <summary>
    /// Extension class, for easy converting the encoding strings, etc.
    /// </summary>
    public static class Extension
    {
        /// <summary>
        /// Copies the given array, into a new array.
        /// </summary>
        /// <param name="sourceData">The source data.</param>
        /// <param name="startIdx">The starting index to copy.</param>
        /// <param name="length">The amount of bytes to copy.</param>
        /// <returns>The copy of the given string, restricted by the length parameter.</returns>
        public static byte[] Copy(this byte[] sourceData, int startIdx, int length)
        {
            byte[] copy = new byte[length];
            Array.Copy(sourceData, startIdx, copy, 0, length);
            return copy;
        }

        /// <summary>
        /// Converts a byte array (UTF-8), to a converted string.
        /// </summary>
        /// <param name="byteArray">The byte array to convert.</param>
        /// <returns>A converted byte array.</returns>
        public static string FromUtf8(this byte[] byteArray)
        {
            // ISO-8859-1 is Latin1
            Encoding latin1 = Encoding.GetEncoding("ISO-8859-1");
            byte[] isoBytes = Encoding.Convert(Encoding.UTF8, latin1, byteArray, 0, byteArray.Length);
            string converted = latin1.GetString(isoBytes);
            return converted;
        }

        /// <summary>
        /// Converts the given string to Latin1 encoding.
        /// </summary>
        /// <param name="str">The string to encode.</param>
        /// <returns>The encoded string.</returns>
        public static string ToLatin1(this string str)
        {
            // ISO-8859-1 is Latin1
            Encoding iso = Encoding.GetEncoding("ISO-8859-1");
            Encoding utf8 = Encoding.UTF8;
            byte[] utfBytes = utf8.GetBytes(str);
            byte[] isoBytes = Encoding.Convert(utf8, iso, utfBytes);
            return iso.GetString(isoBytes);
        }

        /// <summary>
        /// Converts the given string to a UTF8 byte array.
        /// </summary>
        /// <param name="str">The string to convert.</param>
        /// <returns>The UTF8 byte array.</returns>
        public static byte[] ToUtf8(this string str)
        {
            // ISO-8859-1 is Latin1
            Encoding iso = Encoding.GetEncoding("ISO-8859-1");
            Encoding utf8 = Encoding.UTF8;
            byte[] utfBytes = utf8.GetBytes(str);
            return Encoding.Convert(iso, utf8, utfBytes);
        }
    }

    /// <summary>
    /// The simple crypt class.
    /// Used to encrypt, and decrtypt files.
    /// </summary>
    public class SimpleCrypt
    {
        /// <summary>
        /// The CRC table.
        /// </summary>
        private readonly ushort[] crcTable = { 0x0000, 0x1081, 0x2102, 0x3183, 0x4204, 0x5285, 0x6306, 0x7387, 0x8408, 0x9489, 0xa50a, 0xb58b, 0xc60c, 0xd68d, 0xe70e, 0xf78f };

        /// <summary>
        /// The key parts (the splitted key).
        /// </summary>
        private readonly List<char> keyParts;

        /// <summary>
        /// The compression mode.
        /// </summary>
        private CompressionMode compressionMode;

        /// <summary>
        /// The key.
        /// </summary>
        private ulong key;

        /// <summary>
        /// The protection mode.
        /// </summary>
        private IntegrityProtectionMode protectionMode;

        /// <summary>
        /// Initializes a new instance of the <see cref="SimpleCrypt"/> class.
        /// Constructs a SimpleCrypt instance without a valid key set on it.
        /// </summary>
        public SimpleCrypt()
        {
            this.key = 0;
            this.compressionMode = CompressionMode.CompressionAuto;
            this.protectionMode = IntegrityProtectionMode.ProtectionChecksum;
            this.keyParts = new List<char>(8);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SimpleCrypt"/> class.
        /// Constructs a SimpleCrypt instance and initializes it with the given key.
        /// </summary>
        /// <param name="key">The key to initialize with.</param>
        public SimpleCrypt(ulong key)
        {
            this.key = key;
            this.compressionMode = CompressionMode.CompressionAuto;
            this.protectionMode = IntegrityProtectionMode.ProtectionChecksum;
            this.keyParts = new List<char>(8);

            // Split the key into 8 chunks.
            this.SplitKey();
        }

        /// <summary>
        /// enum to describe options that have been used for the encryption. Currently only one, but
        /// that only leaves room for future extensions like adding a cryptographic hash...
        /// </summary>
        [Flags]
        internal enum CryptoFlag
        {
            /// <summary>
            /// No crypto used.
            /// </summary>
            CryptoFlagNone = 0,

            /// <summary>
            /// Crypto based on compression.
            /// </summary>
            CryptoFlagCompression = 0x01,

            /// <summary>
            /// Crypto based on the checksum.
            /// </summary>
            CryptoFlagChecksum = 0x02,

            /// <summary>
            /// Crypto based on a SHA1 hash.
            /// </summary>
            CryptoFlagHash = 0x04,
        }

        /// <summary>
        /// Converts the Error enum to a readable text (for throwing exceptions).
        /// </summary>
        /// <param name="error">The error to convert.</param>
        /// <returns>A string, containing some more info about the error.</returns>
        public static string GetCryptoError(Error error)
        {
            string errorString;
            switch (error)
            {
                case Error.ErrorNoError:
                    errorString = "No error occurred";
                    break;

                case Error.ErrorNoKeySet:
                    errorString = "No key was set. You can not encrypt or decrypt without a valid key.";
                    break;

                case Error.ErrorUnknownVersion:
                    errorString = "The version of this data is unknown, or the data is otherwise not valid.";
                    break;

                case Error.ErrorIntegrityFailed:
                    errorString = "The integrity check of the data failed. Perhaps the wrong key was used.";
                    break;

                default:
                    errorString = "Unknown error";
                    break;
            }

            return errorString;
        }

        /// <summary>
        /// Compresses the data, at the same way the QT method QCompress does.
        /// Adds also 4 bytes at the beginning, which contains the length of the raw uncompressed data.
        /// </summary>
        /// <param name="data">The data to compress.</param>
        /// <returns>The compressed data.</returns>
        public static byte[] QCompress(byte[] data)
        {
            byte[] compressArray;

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (ZLibStream zLibStream = new ZLibStream(memoryStream, CompressionLevel.SmallestSize))
                {
                    zLibStream.Write(data, 0, data.Length);
                }

                compressArray = memoryStream.ToArray();
            }

            byte[] header = new byte[4];
            header[0] = (byte)(data.Length >> 24);
            header[1] = (byte)(data.Length >> 16);
            header[2] = (byte)(data.Length >> 8);
            header[3] = (byte)(data.Length >> 0);

            byte[] returnData = new byte[header.Length + compressArray.Length];
            Array.Copy(header, 0, returnData, 0, header.Length);
            Array.Copy(compressArray, 0, returnData, 4, compressArray.Length);
            return returnData;
        }

        /// <summary>
        /// The implementation of the QT QUncompress method.
        /// This method adds four bytes at the beginning, which contains the uncompressed size.
        /// </summary>
        /// <param name="data">The data to uncompress.</param>
        /// <returns>The uncompressed data.</returns>
        public static byte[] QUncompress(byte[] data)
        {
            // The first 4 bytes, contains the expected size. This is in big-endian format.
            // Remove those 4 bytes, before using the ZLIB stream.
            byte[] expectedSizeArr = data.Copy(0, 4);
            Array.Reverse(expectedSizeArr);
            int expectedSize = BitConverter.ToInt32(expectedSizeArr);

            data = data.Copy(4, data.Length - 4);
            byte[] decompressedArray;

            using (MemoryStream decompressedStream = new MemoryStream())
            {
                using (MemoryStream compressStream = new MemoryStream(data))
                {
                    using (ZLibStream deflateStream = new ZLibStream(compressStream, System.IO.Compression.CompressionMode.Decompress))
                    {
                        deflateStream.CopyTo(decompressedStream);
                    }
                }

                decompressedArray = decompressedStream.ToArray();

                if (decompressedArray.Length != expectedSize)
                {
                    throw new Exception(string.Format("The expected length {0}, does not match the deflated stream length {1}", expectedSize, data.Length));
                }
            }

            return decompressedArray;
        }

        /// <summary>
        /// Decrypts a cyphertext string encrypted with this class with the set key back to the
        /// plain text version.
        /// If an error occured, such as non-matching keys between encryption and decryption,
        /// an empty string or a string containing nonsense may be returned.
        /// </summary>
        /// <param name="cyphertext">The cyphertext to decrypt.</param>
        /// <returns>The decrypted byte array.</returns>
        public byte[] DecryptToByteArray(string cyphertext)
        {
            byte[] cyphertextArray = Convert.FromBase64String(cyphertext.ToLatin1());
            return this.DecryptToByteArray(cyphertextArray);
        }

        /// <summary>
        /// Decrypts a cyphertext binary encrypted with this class with the set key back to the
        /// plain text version.
        /// If an error occured, such as non-matching keys between encryption and decryption,
        /// an empty string or a string containing nonsense may be returned.
        /// </summary>
        /// <param name="cypher">The array to decrypt.</param>
        /// <returns>The decrypted byte array.</returns>
        public byte[] DecryptToByteArray(byte[] cypher)
        {
            if (this.keyParts.Count == 0)
            {
                throw new Exception(GetCryptoError(Error.ErrorNoKeySet));
            }

            byte[] byteArray = cypher;

            if (cypher.Length < 3)
            {
                return Array.Empty<byte>();
            }

            char version = (char)byteArray[0];

            if (version != 3)
            {
                // We only work with version 3
                throw new Exception(GetCryptoError(Error.ErrorUnknownVersion));
            }

            CryptoFlag flags = (CryptoFlag)byteArray[1];

            byteArray = byteArray.Copy(2, byteArray.Length - 2);

            int pos = 0;
            int cnt = byteArray.Length;
            char lastChar = (char)0;

            while (pos < cnt)
            {
                char currentChar = (char)byteArray[pos];
                byteArray[pos] = (byte)(byteArray[pos] ^ lastChar ^ this.keyParts[pos % 8]);
                lastChar = currentChar;
                ++pos;
            }

            // Chop off the random number at the start
            byteArray = byteArray.Copy(1, byteArray.Length - 1);

            bool integrityOk = true;
            if (flags.HasFlag(CryptoFlag.CryptoFlagChecksum))
            {
                if (byteArray.Length < 2)
                {
                    throw new Exception(GetCryptoError(Error.ErrorIntegrityFailed));
                }

                ushort storedChecksum = (ushort)(byteArray[0] | ((ushort)byteArray[1]) << 8);
                byteArray = byteArray.Copy(2, byteArray.Length - 2);

                ushort checksum = this.QChecksum(byteArray);
                integrityOk = checksum == storedChecksum;
            }
            else if (flags.HasFlag(CryptoFlag.CryptoFlagHash))
            {
                if (byteArray.Length < 20)
                {
                    throw new Exception(GetCryptoError(Error.ErrorIntegrityFailed));
                }

                byte[] storedHash = byteArray.Copy(0, 20);
                byteArray = byteArray.Copy(20, byteArray.Length - 20);
                byte[] computedHash = Hash(byteArray);
                integrityOk = IsArrayEqual(computedHash, storedHash);
            }

            if (!integrityOk)
            {
                throw new Exception(GetCryptoError(Error.ErrorIntegrityFailed));
            }

            if (flags.HasFlag(CryptoFlag.CryptoFlagCompression))
            {
                byteArray = QUncompress(byteArray);
            }

            return byteArray;
        }

        /// <summary>
        /// Decrypts a cyphertext string encrypted with this class with the set key back to the
        /// plain text version.
        /// If an error occured, such as non-matching keys between encryption and decryption,
        /// an empty string or a string containing nonsense may be returned.
        /// </summary>
        /// <param name="cyphertext">The cyphertext to decrypt.</param>
        /// <returns>The decrypted string.</returns>
        public string DecryptToString(string cyphertext)
        {
            byte[] cyphertextArray = Convert.FromBase64String(cyphertext.ToLatin1());
            byte[] plaintextArray = this.DecryptToByteArray(cyphertextArray);
            string plaintext = plaintextArray.FromUtf8();
            return plaintext;
        }

        /// <summary>
        /// Decrypts a cyphertext binary encrypted with this class with the set key back to the
        /// plain text version.
        /// If an error occured, such as non-matching keys between encryption and decryption,
        /// an empty string or a string containing nonsense may be returned.
        /// </summary>
        /// <param name="cypher">The binary encrypted byte array.</param>
        /// <returns>A UTF-8 string.</returns>
        public string DecryptToString(byte[] cypher)
        {
            byte[] byteArray = this.DecryptToByteArray(cypher);
            return byteArray.FromUtf8();
        }

        /// <summary>
        /// Encrypts the plaintext string with the key the class was initialized with, and returns
        /// a binary cyphertext in a the result.
        /// This method returns a byte array, that is useable for storing a binary format. If you need
        /// a string you can store in a text file, use encryptToString() instead.
        /// </summary>
        /// <param name="plaintext">The plain text to encrypt.</param>
        /// <returns>The encrypted byte array.</returns>
        public byte[] EncryptToByteArray(string plaintext)
        {
            byte[] plainTextArray = plaintext.ToUtf8();
            return this.EncryptToByteArray(plainTextArray);
        }

        /// <summary>
        /// Encrypts the plaintext with the key the class was initialized with, and returns
        /// a binary cyphertext in a the result.
        /// This method returns a byte array, that is useable for storing a binary format. If you need
        /// a string you can store in a text file, use encryptToString() instead.
        /// </summary>
        /// <param name="plaintext">The byte array to encrypt.</param>
        /// <returns>The encrypted byte array.</returns>
        /// <exception cref="Exception">Thrown when the key is invalid.</exception>
        public byte[] EncryptToByteArray(byte[] plaintext)
        {
            if (this.keyParts.Count == 0)
            {
                throw new Exception(GetCryptoError(Error.ErrorNoKeySet));
            }

            byte[] byteArray = plaintext;

            CryptoFlag flags = CryptoFlag.CryptoFlagNone;
            if (this.compressionMode == CompressionMode.CompressionAlways)
            {
                byteArray = QCompress(byteArray);
                flags |= CryptoFlag.CryptoFlagCompression;
            }
            else if (this.compressionMode == CompressionMode.CompressionAuto)
            {
                byte[] compressed = QCompress(byteArray);
                if (compressed.Length < byteArray.Length)
                {
                    byteArray = compressed;
                    flags |= CryptoFlag.CryptoFlagCompression;
                }
            }

            byte[] integrityProtection = Array.Empty<byte>();
            if (this.protectionMode == IntegrityProtectionMode.ProtectionChecksum)
            {
                flags |= CryptoFlag.CryptoFlagChecksum;
                ushort checkSum = this.QChecksum(byteArray);
                integrityProtection = new byte[2];
                integrityProtection[0] = (byte)checkSum;
                integrityProtection[1] = (byte)(checkSum >> 8);
            }
            else if (this.protectionMode == IntegrityProtectionMode.ProtectionHash)
            {
                flags |= CryptoFlag.CryptoFlagHash;
                integrityProtection = Hash(byteArray);
            }

            // Prepend a random char to the string
            Random r = new Random();
            char randomChar = (char)r.Next();

            byte[] data = new byte[integrityProtection.Length + byteArray.Length + 1];
            data[0] = (byte)randomChar;
            Array.Copy(integrityProtection, 0, data, 1, integrityProtection.Length);
            Array.Copy(byteArray, 0, data, integrityProtection.Length + 1, byteArray.Length);

            int pos = 0;
            char lastChar = (char)0;
            int cnt = data.Length;

            while (pos < cnt)
            {
                data[pos] = (byte)(data[pos] ^ this.keyParts[pos % 8] ^ lastChar);
                lastChar = (char)data[pos];
                ++pos;
            }

            byte[] resultArray = new byte[data.Length + 2];

            // version for future updates to algorithm
            resultArray[0] = 0x03;

            // encryption flags
            resultArray[1] = (byte)flags;
            Array.Copy(data, 0, resultArray, 2, data.Length);
            return resultArray;
        }

        /// <summary>
        /// Encrypts the plaintext string with the key the class was initialized with, and returns
        /// a cyphertext the result.The result is a base64 encoded version of the binary array that is the
        /// actual result of the string, so it can be stored easily in a text format.
        /// </summary>
        /// <param name="plaintext">The string to encrypt.</param>
        /// <returns>The encrypted string.</returns>
        public string EncryptToString(byte[] plaintext)
        {
            byte[] cypher = this.EncryptToByteArray(plaintext);
            string cypherString = FromLatin1(Convert.ToBase64String(cypher));
            return cypherString;
        }

        /// <summary>
        /// Encrypts the plaintext with the key the class was initialized with, and returns
        /// a cyphertext the result.The result is a base64 encoded version of the binary array that is the
        /// actual result of the encryption, so it can be stored easily in a text format.
        /// </summary>
        /// <param name="plaintext"> The plain text to encrypt.</param>
        /// <returns>The encrypted string.</returns>
        public string EncryptToString(string plaintext)
        {
            byte[] plaintextArray = plaintext.ToUtf8();
            byte[] cypher = this.EncryptToByteArray(plaintextArray);
            string cypherString = FromLatin1(Convert.ToBase64String(cypher));
            return cypherString;
        }

        /// <summary>
        /// Sets the compression mode to use when encrypting data. The default mode is Auto.
        /// Note that decryption is not influenced by this mode, as the decryption recognizes
        /// what mode was used when encrypting.
        /// </summary>
        /// <param name="mode">The encryption mode to set.</param>
        public void SetCompressionMode(CompressionMode mode)
        {
            this.compressionMode = mode;
        }

        /// <summary>
        /// Sets the integrity mode to use when encrypting data. The default mode is Checksum.
        /// Note that decryption is not influenced by this mode, as the decryption recognizes
        /// what mode was used when encrypting.
        /// </summary>
        /// <param name="mode">The protection mode to set.</param>
        public void SetIntegrityProtectionMode(IntegrityProtectionMode mode)
        {
            this.protectionMode = mode;
        }

        /// <summary>
        /// (Re-) initializes the key with the given @arg key.
        /// </summary>
        /// <param name="key">The key to set.</param>
        public void SetKey(ulong key)
        {
            this.key = key;
            this.SplitKey();
        }

        /// <summary>
        /// Converts a string from latin1 to the UTF encoding.
        /// </summary>
        /// <param name="src">The string source.</param>
        /// <returns>The string in UTF-8  encoding.</returns>
        private static string FromLatin1(string src)
        {
            // ISO-8859-1 is Latin1
            Encoding latin1 = Encoding.GetEncoding("ISO-8859-1");
            byte[] bytes = latin1.GetBytes(src);
            byte[] isoBytes = Encoding.Convert(latin1, Encoding.UTF8, bytes);
            return latin1.GetString(isoBytes);
        }

        /// <summary>
        /// Generates a SHA1 hash for the byte array.
        /// </summary>
        /// <param name="data">The data to generate a SHA1 for.</param>
        /// <returns>The computed hash.</returns>
        private static byte[] Hash(byte[] data)
        {
            SHA1 sha1 = SHA1.Create();
            return sha1.ComputeHash(data);
        }

        /// <summary>
        /// Checks if the two byte arrays are identical.
        /// </summary>
        /// <param name="array1">The first array to compare.</param>
        /// <param name="array2">The second array to compare.</param>
        /// <returns>True when the arrays are equal, otherwise flase.</returns>
        private static bool IsArrayEqual(byte[] array1, byte[] array2)
        {
            if (array1.Length != array2.Length)
            {
                return false;
            }

            for (int i = 0; i < array1.Length; i++)
            {
                if (array1[i] != array2[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Calculates the checksum for given byte array.
        /// Uses the default CRC table.
        /// </summary>
        /// <param name="data">The data to calculate the CRC over.</param>
        /// <returns>The calculated CRC.</returns>
        private ushort QChecksum(byte[] data)
        {
            ushort crc = 0xffff;
            foreach (byte b in data)
            {
                uint x = (uint)b;
                crc = (ushort)(((crc >> 4) & 0x0fff) ^ this.crcTable[(crc ^ x) & 15]);
                x >>= 4;
                crc = (ushort)(((crc >> 4) & 0x0fff) ^ this.crcTable[(crc ^ x) & 15]);
            }

            return (ushort)(~crc & 0xffff);
        }

        /// <summary>
        /// Splits the key (64 bit) into 8 chunks of 8 bit (char).
        /// </summary>
        private void SplitKey()
        {
            for (int i = 0; i < 8; i++)
            {
                ulong part = this.key;
                for (int j = i; j > 0; j--)
                {
                    part >>= 8;
                }

                part &= 0xff;
                this.keyParts.Add((char)part);
            }
        }
    }
}