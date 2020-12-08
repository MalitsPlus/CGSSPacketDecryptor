using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using MahApps.Metro.Controls;
using System.Threading;

namespace CGSSPacketDecryptor
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : MetroWindow
    {
        public MainWindow() {
            InitializeComponent();
        }

        private async void EncodedText_TextChanged(object sender, TextChangedEventArgs e) {
            if (string.IsNullOrEmpty((sender as TextBox)?.Text)) {
                return;
            }
            string raw = (sender as TextBox)?.Text ?? "";
            string json = string.Empty;
            string udid = Cryptographer.Get().DecodeUDID("002427o736B153>177=836<841C874k535@2727423<665A283A786n2867613>285o144m537:7467571l718C211;278<4187853;824:662n552:457m417o188m211<627o384B833k882p43624188261841164");
            try {
                json = await Task.Run(() => {
                    return Cryptographer.Get().DecryptData(raw, udid);
                }); 
            } catch (Exception ex) {
                json = ex.Message;
            }
            DecodedText.Text = json;
        }
    }
}
