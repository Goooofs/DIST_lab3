using System;
using System.Diagnostics;
using System.Linq;
using System.Windows.Forms;

namespace DllInjectorGUI
{
    public class InjectorForm : Form
    {
        private Button injectButton;
        private Label infoLabel;

        public InjectorForm()
        {
            this.Text = "DLL Injector";
            this.Size = new System.Drawing.Size(400, 200);
            this.StartPosition = FormStartPosition.CenterScreen;

            infoLabel = new Label();
            infoLabel.Text = "Press the button to inject DLL in TargetProcess.exe.";
            infoLabel.AutoSize = true;

            injectButton = new Button();
            injectButton.Text = "Run the injection";
            injectButton.AutoSize = true;
            injectButton.Click += InjectButton_Click;

            FlowLayoutPanel panel = new FlowLayoutPanel();
            panel.Dock = DockStyle.Fill;
            panel.Controls.Add(infoLabel);
            panel.Controls.Add(injectButton);

            this.Controls.Add(panel);
        }

        private void InjectButton_Click(object sender, EventArgs e)
        {
            Process[] targetProcesses = Process.GetProcessesByName("TargetProcess");
            if (targetProcesses == null || targetProcesses.Length == 0)
            {
                MessageBox.Show("TargetProcess.exe process was not found.", "error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            string pid = targetProcesses.First().Id.ToString();

            string dllPath = @"X:\DLL_EXE\DllInjectorAsDll.dll";

            string arguments = $"\"{dllPath}\", HelperFunc {pid}";

            ProcessStartInfo psi = new ProcessStartInfo("rundll32.exe", arguments)
            {
                CreateNoWindow = true,
                UseShellExecute = false
            };

            try
            {
                Process proc = Process.Start(psi);
                proc.WaitForExit();
                // MessageBox.Show("The injection is successful!", "success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Injection error: {ex.Message}", "error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        [STAThread]
        public static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new InjectorForm());
        }
    }
}
