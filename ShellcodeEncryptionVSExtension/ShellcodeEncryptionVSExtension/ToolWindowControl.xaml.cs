using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.IO;

namespace ShellcodeEncryptionVSExtension
{
    public partial class ToolWindowControl : UserControl
    {
        public ToolWindowControl()
        {
            InitializeComponent();
            EncryptionMethodComboBox.SelectedIndex = 0; // Default to XOR
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Clean up input shellcode
                string shellcode = ShellcodeTextBox.Text
                                   .Replace("\"", "")
                                   .Replace("\n", "")
                                   .Replace("\r", "")
                                   .Replace("\\x", "")
                                   .Replace(" ", "");

                string keyText = KeyTextBox.Text;

                // Convert shellcode to bytes
                byte[] shellcodeBytes = Enumerable.Range(0, shellcode.Length / 2)
                                                 .Select(i => Convert.ToByte(shellcode.Substring(i * 2, 2), 16))
                                                 .ToArray();

                // Convert key to bytes
                byte[] keyBytes = Encoding.UTF8.GetBytes(keyText);

                // Get selected encryption method
                string encryptionMethod = ((ComboBoxItem)EncryptionMethodComboBox.SelectedItem).Content.ToString();

                byte[] encryptedShellcode;
                string debugInfo = "Shellcode bytes: " + string.Join(", ", shellcodeBytes.Select(b => $"0x{b:x2}")) + "\n";
                debugInfo += "Key bytes: " + string.Join(", ", keyBytes.Select(b => $"0x{b:x2}")) + "\n";

                // Perform encryption based on selected method
                if (encryptionMethod == "XOR")
                {
                    encryptedShellcode = EncryptXOR(shellcodeBytes, keyBytes);

                    // Add debug information for the first 10 bytes
                    for (int i = 0; i < Math.Min(10, shellcodeBytes.Length); i++)
                    {
                        byte keyByte = keyBytes[i % keyBytes.Length];
                        byte shellcodeByte = shellcodeBytes[i];
                        byte result = encryptedShellcode[i];
                        debugInfo += $"Index {i}: 0x{shellcodeByte:x2} XOR 0x{keyByte:x2} = 0x{result:x2}\n";
                    }
                }
                else if (encryptionMethod == "AES")
                {
                    // Call AES encryption method
                    encryptedShellcode = EncryptAES(shellcodeBytes, keyBytes);
                    debugInfo += "AES encryption used.\n";
                }
                else
                {
                    throw new NotSupportedException($"Encryption method '{encryptionMethod}' not supported.");
                }

                // Result in shellcode format
                string hexResult = string.Concat(encryptedShellcode.Select(b => $"\\x{b:x2}"));
                HexResultBox.Text = hexResult;


                // Show debug information
                //MessageBox.Show(debugInfo, "Debug Info", MessageBoxButton.OK);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK);
            }
        }

        private byte[] EncryptXOR(byte[] data, byte[] key)
        {
            byte[] output = new byte[data.Length];
            int keyLength = key.Length;

            for (int i = 0; i < data.Length; i++)
            {
                output[i] = (byte)(data[i] ^ key[i % keyLength]); // XOR with cycling key
            }

            return output;
        }

        private byte[] EncryptAES(byte[] data, byte[] key)
        {
            try
            {
                // Ensure the key has the correct size for AES (16, 24, or 32 bytes)
                byte[] aesKey = GetValidAESKey(key);

                // Create a random initialization vector
                byte[] iv = new byte[16];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(iv);
                }

                // Create AES encryption object
                using (Aes aes = Aes.Create())
                {
                    aes.Key = aesKey;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    // Create encryptor
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    // Encrypt the data
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        // First write the IV
                        msEncrypt.Write(iv, 0, iv.Length);

                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            csEncrypt.Write(data, 0, data.Length);
                            csEncrypt.FlushFinalBlock();
                        }

                        return msEncrypt.ToArray();
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"AES Encryption Error: {ex.Message}", "Error", MessageBoxButton.OK);
                return null;
            }
        }

        private byte[] GetValidAESKey(byte[] inputKey)
        {
            // AES requires a key of 16, 24 or 32 bytes (128, 192 or 256 bits)
            if (inputKey.Length == 16 || inputKey.Length == 24 || inputKey.Length == 32)
            {
                return inputKey;
            }

            // If key is less than 16 bytes, pad to 16
            if (inputKey.Length < 16)
            {
                byte[] newKey = new byte[16];
                Array.Copy(inputKey, newKey, inputKey.Length);
                // Fill the rest with constant values
                for (int i = inputKey.Length; i < 16; i++)
                {
                    newKey[i] = 0x41; // ASCII for 'A'
                }
                return newKey;
            }

            // If key is greater than 16 but less than 24, pad to 24
            if (inputKey.Length < 24)
            {
                byte[] newKey = new byte[24];
                Array.Copy(inputKey, newKey, inputKey.Length);
                for (int i = inputKey.Length; i < 24; i++)
                {
                    newKey[i] = 0x41; // ASCII for 'A'
                }
                return newKey;
            }

            // If key is greater than 24 but less than 32, pad to 32
            if (inputKey.Length < 32)
            {
                byte[] newKey = new byte[32];
                Array.Copy(inputKey, newKey, inputKey.Length);
                for (int i = inputKey.Length; i < 32; i++)
                {
                    newKey[i] = 0x41; // ASCII for 'A'
                }
                return newKey;
            }

            // If key is greater than 32, truncate to 32
            byte[] finalKey = new byte[32];
            Array.Copy(inputKey, finalKey, 32);
            return finalKey;
        }
    }
}