using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using General;
using Models;
using Token;
using Encryption;

namespace CreateTokenApplication
{
    public partial class testApp : Form
    {
        private void ClearDefaults()
        {
            textId.Text = "";
            textName.Text = "";
            textSurname.Text = "";
            textCompany.Text = "";
            textApplication.Text = "";
            textIp.Text = "";
        }

        private void SetDefaults(User user = null)
        {
            user = user ?? new User
            {
                Id = "1",
                Name = "name",
                Surname = "surname",
                Company = "company",
                Application = "application",
                Ip = "192.168.0.11"
            };

            textId.Text = user.Id;
            textName.Text = user.Name;
            textSurname.Text = user.Surname;
            textCompany.Text = user.Company;
            textApplication.Text = user.Application;
            textIp.Text = user.Ip;            
        }
        
        public testApp()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            Control.CheckForIllegalCrossThreadCalls = false;
        }

        private void BtnSetDefault_Click(object sender, EventArgs e)
        {
            SetDefaults();
        }

        private void BtnCreateToken_Click(object sender, EventArgs e)
        {
            DateTime ExpirationDateTime = DateTime.UtcNow.AddDays(Convert.ToInt16(textExpireDay.Text));

            User user = new User
            {
                Id = textId.Text,
                Name = textName.Text,
                Surname = textSurname.Text,
                Company = textCompany.Text,
                Application = textApplication.Text,
                Ip = textIp.Text,
                CreatedDateTime = DateTime.Now.ToString(),
                ExpirationDateTime = ExpirationDateTime.ToString()
            };
            textJson.Text = Newtonsoft.Json.JsonConvert.SerializeObject(user);

            OperationResult operation = TokenProcess.EncodeToken(textJson.Text, ExpirationDateTime);
            //or this one : OperationResult operation = SymmetricalEncryption.DESEncryptedLimitedTime(textJson.Text, ExpirationDateTime); 
            textToken.Text = operation.Message;

            textJson.Text = "";
            ClearDefaults();
        }

        private void BtnConvertToken_Click(object sender, EventArgs e)
        {
            OperationResult operation = TokenProcess.DecodeToken(textToken.Text);
            //or this one : OperationResult operation = SymmetricalEncryption.DESDecryptedLimitedTime(textToken.Text);
            textJson.Text = operation.Message;

            if (operation.Result)
            {
                User user = Newtonsoft.Json.JsonConvert.DeserializeObject<User>(operation.Message);
                SetDefaults(user);
            }
        }
    }
}
