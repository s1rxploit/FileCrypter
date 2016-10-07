using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography;

namespace Filecryption
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }



        // Rfc2898DeriveBytes constants:
        public readonly byte[] salt = new byte[8] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // Must be at least eight bytes.  MAKE THIS SALTIER!
        public const int iterations = 1042; // Recommendation is >= 1000.
        public string sourceFilename;
        public string destinationFilename;
        public string password;
        public string realEx;
        public string sourceFilenameBack, destinationFilenameBack, passwordBack;

        private void Form1_Load(object sender, EventArgs e)
        {
        }

        /// <summary>Decrypt a file.</summary>
        /// <remarks>NB: "Padding is invalid and cannot be removed." is the Universal CryptoServices error.  Make sure the password, salt and iterations are correct before getting nervous.</remarks>
        /// <param name="sourceFilename">The full path and name of the file to be decrypted.</param>
        /// <param name="destinationFilename">The full path and name of the file to be output.</param>
        /// <param name="password">The password for the decryption.</param>
        /// <param name="salt">The salt to be applied to the password.</param>
        /// <param name="iterations">The number of iterations Rfc2898DeriveBytes should use before generating the key and initialization vector for the decryption.</param>
        public void DecryptFile(string sourceFilename, string destinationFilename, string password, byte[] salt, int iterations)
        {
            AesManaged aes = new AesManaged();
            aes.BlockSize = aes.LegalBlockSizes[0].MaxSize;
            aes.KeySize = aes.LegalKeySizes[0].MaxSize;
            // NB: Rfc2898DeriveBytes initialization and subsequent calls to   GetBytes   must be eactly the same, including order, on both the encryption and decryption sides.
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt, iterations);
            aes.Key = key.GetBytes(aes.KeySize / 8);
            aes.IV = key.GetBytes(aes.BlockSize / 8);
            aes.Mode = CipherMode.CBC;
            ICryptoTransform transform = aes.CreateDecryptor(aes.Key, aes.IV);

            using (FileStream destination = new FileStream(destinationFilename, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                using (CryptoStream cryptoStream = new CryptoStream(destination, transform, CryptoStreamMode.Write))
                {
                    try
                    {
                        using (FileStream source = new FileStream(sourceFilename, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            source.CopyTo(cryptoStream);
                        }
                    }
                    catch (CryptographicException exception)
                    {
                        if (exception.Message == "Padding is invalid and cannot be removed.")
                            throw new ApplicationException("Universal Microsoft Cryptographic Exception (Not to be believed!)", exception);
                        else
                            throw;
                    }
                }
            }
        }

        /// <summary>Encrypt a file.</summary>
        /// <param name="sourceFilename">The full path and name of the file to be encrypted.</param>
        /// <param name="destinationFilename">The full path and name of the file to be output.</param>
        /// <param name="password">The password for the encryption.</param>
        /// <param name="salt">The salt to be applied to the password.</param>
        /// <param name="iterations">The number of iterations Rfc2898DeriveBytes should use before generating the key and initialization vector for the decryption.</param>
        public void EncryptFile(string sourceFilename, string destinationFilename, string password, byte[] salt, int iterations)
        {
            AesManaged aes = new AesManaged();
            aes.BlockSize = aes.LegalBlockSizes[0].MaxSize;
            aes.KeySize = aes.LegalKeySizes[0].MaxSize;
            // NB: Rfc2898DeriveBytes initialization and subsequent calls to   GetBytes   must be eactly the same, including order, on both the encryption and decryption sides.
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt, iterations);
            aes.Key = key.GetBytes(aes.KeySize / 8);
            aes.IV = key.GetBytes(aes.BlockSize / 8);
            aes.Mode = CipherMode.CBC;
            ICryptoTransform transform = aes.CreateEncryptor(aes.Key, aes.IV);

            using (FileStream destination = new FileStream(destinationFilename, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                using (CryptoStream cryptoStream = new CryptoStream(destination, transform, CryptoStreamMode.Write))
                {
                    try
                    {
                        using (FileStream source = new FileStream(sourceFilename, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            source.CopyTo(cryptoStream);
                        }
                    }
                    catch (CryptographicException exception)
                    {
                        if (exception.Message == "Padding is invalid and cannot be removed.")
                            throw new ApplicationException("Universal Microsoft Cryptographic Exception (Not to be believed!)", exception);
                        else
                            throw;
                    }
                }
            }
        }

        public void EncryptFileBackup(string sourceFilenameBack, string destinationFilenameBack, string passwordBack, byte[] salt, int iterations)
        {
            AesManaged aes = new AesManaged();
            aes.BlockSize = aes.LegalBlockSizes[0].MaxSize;
            aes.KeySize = aes.LegalKeySizes[0].MaxSize;
            // NB: Rfc2898DeriveBytes initialization and subsequent calls to   GetBytes   must be eactly the same, including order, on both the encryption and decryption sides.
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(passwordBack, salt, iterations);
            aes.Key = key.GetBytes(aes.KeySize / 8);
            aes.IV = key.GetBytes(aes.BlockSize / 8);
            aes.Mode = CipherMode.CBC;
            ICryptoTransform transform = aes.CreateEncryptor(aes.Key, aes.IV);

            using (FileStream destination = new FileStream(destinationFilenameBack, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                using (CryptoStream cryptoStream = new CryptoStream(destination, transform, CryptoStreamMode.Write))
                {
                    try
                    {
                        using (FileStream source = new FileStream(sourceFilenameBack, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            source.CopyTo(cryptoStream);
                        }
                    }
                    catch (CryptographicException exception)
                    {
                        if (exception.Message == "Padding is invalid and cannot be removed.")
                            throw new ApplicationException("Universal Microsoft Cryptographic Exception (Not to be believed!)", exception);
                        else
                            throw;
                    }
                }
            }
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        //browse File
        private void button1_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog1 = new OpenFileDialog();
            openFileDialog1.Filter = "All files (*.*)|*.*|Encrypted Files (*.foxenc)|*.foxenc";
            openFileDialog1.Title = "Open an Encrypted/Decerpted File";
            openFileDialog1.ShowDialog();

            sourceFilename = openFileDialog1.FileName;

            this.textBox1.Text = "" + sourceFilename;

        }

        //Not Used!
        private void button2_Click(object sender, EventArgs e)
        {

            SaveFileDialog saveFileDialog1 = new SaveFileDialog();
            saveFileDialog1.Filter = "All files (*.*)|*.*";
            saveFileDialog1.Title = "Save an Encrypted/Decerpted File";
            saveFileDialog1.ShowDialog();

            destinationFilename = saveFileDialog1.FileName;

        }

        //Encrypt File
        private void button3_Click(object sender, EventArgs e)
        {
            sourceFilename = this.textBox1.Text;
            password = textBox2.Text;

            if (password != null)
            {
                destinationFilename = sourceFilename + ".foxenc";
                EncryptFile(sourceFilename, destinationFilename, password, salt, iterations);
            }
            else
            {
                MessageBox.Show("Enter a password");
                return;
            }

            if (checkBox1.Checked)
            {
                string lines = "Password to the file: " + destinationFilename + " = " + password;
                System.IO.StreamWriter file = new System.IO.StreamWriter(sourceFilename + ".foxtoback");
                file.WriteLine(lines);
                file.Close();
                sourceFilenameBack = sourceFilename + ".foxtoback";
                destinationFilenameBack = destinationFilename + ".foxback";
                passwordBack = "Ecas_PqhlH_-FwNZtYUYvmezjBmfrVNIkO_f1NSTrTRNF6fcLXlft4iLRXERMq_uJfV29-jv4JkKyyUyV54DLGByQApdEVkPiPHEUdNvtQ2p9kkAiIy6UsZWjQgjlWHXzKmQMnDXh9zcYcF_e5BTTtHqs-1hyGVX9DWXfeW8vLNXWMavvWXBn3qySbMMLAtnHBOBBRZslhjKVcQwuruZccG-CeD0lnTmA0sarYhkJMT2d0MvJd-Zgs5z_7Vi0oBKc42VyWivCI6qLDeNGqGepypAjNi9sUt52ykko6PUWFhHb_ZFWDAJ8-rcXlqbSV7tCucJouvTswRz6dNyjnvfDyADLl4x5nF74Of-a7uBFHr7chlvi_it6jDpBAU1fw_yRKn4gr76h3H9OzURr_phmFWYKQWZLCVwG8rNHnaq6zuk8kyM2jLO2q6Qd0WvhxBaBfKHvRTPrKR54e5pcbQBtT8AMA2i4tNE3swiZ3Q9gVY5o45sxEDj";
                EncryptFileBackup(sourceFilenameBack, destinationFilenameBack, passwordBack, salt, iterations);
                File.Delete(sourceFilenameBack);
            }
            else
            {

            }
            File.Delete(sourceFilename);
            MessageBox.Show("File Encrypted");
        }

        //Not Used!
        private void button5_Click(object sender, EventArgs e)
        {
        }

        //Decrypt File
        private void button4_Click(object sender, EventArgs e)
        {
            password = textBox2.Text;
            sourceFilename = this.textBox1.Text;

            if (password != null)
            {

                destinationFilename = sourceFilename;

                string NewDestinationFilename = destinationFilename;

                int index = NewDestinationFilename.IndexOf(".foxenc");

                if (index != -1)
                {
                    NewDestinationFilename = NewDestinationFilename.Remove(index);
                }

                destinationFilename = NewDestinationFilename;

                DecryptFile(sourceFilename, destinationFilename, password, salt, iterations);
            }
            else
            {
                MessageBox.Show("Enter a password");
                return;
            }

            File.Delete(sourceFilename);

            MessageBox.Show("File Decrypted");
        }
    }
}
