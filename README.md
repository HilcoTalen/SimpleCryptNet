# SimpleCryptNet
C# (.NET) implementation of the SimpleCrypt used int QT


Usage like:

// Encrypt

SimpleCrypt simpleCrypt = new SimpleCrypt(0x3456ABCD);
simpleCrypt.SetIntegrityProtectionMode(IntegrityProtectionMode.ProtectionHash);
simpleCrypt.SetCompressionMode(CompressionMode.CompressionAlways);

string fileContent = File.ReadAllText(filePathText);
byte[] encryptedData = simpleCrypt.EncryptToByteArray(fileContent);
File.WriteAllBytes(filePath, encryptedData);

// Decrypt
SimpleCrypt simpleCrypt = new SimpleCrypt(0x3456ABCD);
string decryptedText = simpleCrypt.DecryptToString(File.ReadAllBytes(filePath));
