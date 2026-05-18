// Minimal Windows Forms GUI for scelot. Builds an scelot.exe command line
// from the user's choices, runs it, and shows stdout in a log box.
//
// Built with csc.exe directly — no MSBuild project required. See build.cmd.
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows.Forms;
using System.Drawing;

namespace ScelotGui {
    class MainForm : Form {
        TextBox tbInput, tbOutput, tbArgs, tbExport, tbNetClass, tbNetMethod;
        ComboBox cbArch, cbExit;
        Button btnInBrowse, btnOutBrowse, btnGenerate, btnLaunch;
        TextBox tbLog;
        CheckBox cbEmitExe;

        string ScelotExe {
            get {
                string root = AppDomain.CurrentDomain.BaseDirectory;
                // Walk up to find scelot.exe; usually one directory up.
                string p = Path.Combine(root, "scelot.exe");
                if (File.Exists(p)) return p;
                p = Path.Combine(Path.GetDirectoryName(root.TrimEnd('\\')), "scelot.exe");
                if (File.Exists(p)) return p;
                p = Path.Combine(Directory.GetCurrentDirectory(), "scelot.exe");
                return p;
            }
        }

        string LauncherExe {
            get {
                string root = AppDomain.CurrentDomain.BaseDirectory;
                string p = Path.Combine(root, @"..\build\tests\out\launcher.exe");
                if (File.Exists(p)) return Path.GetFullPath(p);
                p = Path.Combine(Directory.GetCurrentDirectory(), @"build\tests\out\launcher.exe");
                return p;
            }
        }

        public MainForm() {
            Text = "scelot — PE/.NET to shellcode";
            Size = new Size(680, 560);
            MinimumSize = new Size(560, 460);
            Font = new Font("Segoe UI", 9);

            int y = 12, lblW = 100, fldX = 120, fldW = 440, btnW = 90;

            Label(y, lblW, "Input PE:");
            tbInput = TextField(y, fldX, fldW - btnW - 4);
            btnInBrowse = SmallButton(y, fldX + fldW - btnW, btnW, "Browse…",
                (s, e) => Browse(tbInput, "PE files|*.exe;*.dll|All|*.*"));
            y += 28;

            Label(y, lblW, "Output .bin:");
            tbOutput = TextField(y, fldX, fldW - btnW - 4);
            btnOutBrowse = SmallButton(y, fldX + fldW - btnW, btnW, "Browse…",
                (s, e) => SaveBrowse(tbOutput, "Shellcode|*.bin"));
            y += 28;

            Label(y, lblW, "Architecture:");
            cbArch = Combo(y, fldX, 100, new[] { "auto", "x64", "x86" });
            cbArch.SelectedIndex = 0;
            y += 28;

            Label(y, lblW, "Exit mode:");
            cbExit = Combo(y, fldX, 100, new[] { "exit", "thread", "return" });
            cbExit.SelectedIndex = 0;
            y += 28;

            Label(y, lblW, "Args:");
            tbArgs = TextField(y, fldX, fldW);
            y += 28;

            Label(y, lblW, "Export (DLL):");
            tbExport = TextField(y, fldX, fldW);
            y += 28;

            Label(y, lblW, ".NET class:");
            tbNetClass = TextField(y, fldX, fldW);
            y += 28;

            Label(y, lblW, ".NET method:");
            tbNetMethod = TextField(y, fldX, fldW);
            y += 28;

            cbEmitExe = new CheckBox {
                Left = fldX, Top = y, Width = 200, Text = "Also emit launcher .exe",
                Anchor = AnchorStyles.Top | AnchorStyles.Left
            };
            Controls.Add(cbEmitExe);
            y += 28;

            btnGenerate = new Button {
                Left = fldX, Top = y, Width = 130, Height = 28,
                Text = "Generate", Anchor = AnchorStyles.Top | AnchorStyles.Left
            };
            btnGenerate.Click += OnGenerate;
            Controls.Add(btnGenerate);

            btnLaunch = new Button {
                Left = fldX + 138, Top = y, Width = 130, Height = 28,
                Text = "Launch .bin",
                Anchor = AnchorStyles.Top | AnchorStyles.Left
            };
            btnLaunch.Click += OnLaunch;
            Controls.Add(btnLaunch);
            y += 36;

            tbLog = new TextBox {
                Left = 12, Top = y, Width = 640, Height = 130,
                Multiline = true, ScrollBars = ScrollBars.Both,
                ReadOnly = true, Font = new Font("Consolas", 9),
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom |
                         AnchorStyles.Left | AnchorStyles.Right
            };
            Controls.Add(tbLog);

            Log("scelot.exe = " + ScelotExe);
            Log("launcher   = " + LauncherExe);
        }

        Label Label(int y, int w, string text) {
            var l = new Label { Left = 12, Top = y + 4, Width = w, Text = text };
            Controls.Add(l);
            return l;
        }

        TextBox TextField(int y, int x, int w) {
            var t = new TextBox {
                Left = x, Top = y, Width = w,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            Controls.Add(t);
            return t;
        }

        Button SmallButton(int y, int x, int w, string text, EventHandler h) {
            var b = new Button {
                Left = x, Top = y - 1, Width = w, Height = 24, Text = text,
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            b.Click += h;
            Controls.Add(b);
            return b;
        }

        ComboBox Combo(int y, int x, int w, string[] items) {
            var c = new ComboBox {
                Left = x, Top = y, Width = w,
                DropDownStyle = ComboBoxStyle.DropDownList
            };
            c.Items.AddRange(items);
            Controls.Add(c);
            return c;
        }

        void Browse(TextBox tb, string filter) {
            using (var d = new OpenFileDialog { Filter = filter }) {
                if (d.ShowDialog(this) == DialogResult.OK) {
                    tb.Text = d.FileName;
                    if (tb == tbInput && string.IsNullOrEmpty(tbOutput.Text)) {
                        tbOutput.Text = Path.ChangeExtension(d.FileName, ".bin");
                    }
                }
            }
        }

        void SaveBrowse(TextBox tb, string filter) {
            using (var d = new SaveFileDialog { Filter = filter }) {
                if (!string.IsNullOrEmpty(tb.Text)) d.FileName = tb.Text;
                if (d.ShowDialog(this) == DialogResult.OK) tb.Text = d.FileName;
            }
        }

        void Log(string s) {
            tbLog.AppendText(s + Environment.NewLine);
        }

        string Quote(string s) {
            if (string.IsNullOrEmpty(s)) return "\"\"";
            return "\"" + s.Replace("\"", "\\\"") + "\"";
        }

        void OnGenerate(object sender, EventArgs e) {
            string exe = ScelotExe;
            if (!File.Exists(exe)) {
                MessageBox.Show(this, "scelot.exe not found at: " + exe,
                                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (string.IsNullOrEmpty(tbInput.Text) || string.IsNullOrEmpty(tbOutput.Text)) {
                MessageBox.Show(this, "Specify input PE and output .bin paths.",
                                "Missing fields", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var sb = new StringBuilder();
            sb.Append(Quote(tbInput.Text));
            sb.Append(" -o ").Append(Quote(tbOutput.Text));
            if (cbArch.SelectedIndex > 0) sb.Append(" -a ").Append(cbArch.Text);
            sb.Append(" --exit ").Append(cbExit.Text);
            if (!string.IsNullOrEmpty(tbExport.Text))    sb.Append(" -e ").Append(Quote(tbExport.Text));
            if (!string.IsNullOrEmpty(tbNetClass.Text))  sb.Append(" -c ").Append(Quote(tbNetClass.Text));
            if (!string.IsNullOrEmpty(tbNetMethod.Text)) sb.Append(" -m ").Append(Quote(tbNetMethod.Text));
            if (!string.IsNullOrEmpty(tbArgs.Text))      sb.Append(" --args ").Append(Quote(tbArgs.Text));
            if (cbEmitExe.Checked) {
                string exePath = Path.ChangeExtension(tbOutput.Text, ".exe");
                sb.Append(" --exe ").Append(Quote(exePath));
            }

            Log("> " + Path.GetFileName(exe) + " " + sb);

            try {
                var psi = new ProcessStartInfo(exe, sb.ToString()) {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = Path.GetDirectoryName(exe)
                };
                using (var p = Process.Start(psi)) {
                    string stdout = p.StandardOutput.ReadToEnd();
                    string stderr = p.StandardError.ReadToEnd();
                    p.WaitForExit();
                    if (!string.IsNullOrEmpty(stdout)) Log(stdout.TrimEnd());
                    if (!string.IsNullOrEmpty(stderr)) Log("[err] " + stderr.TrimEnd());
                    Log("[exit " + p.ExitCode + "]");
                }
            } catch (Exception ex) {
                Log("[exception] " + ex.Message);
            }
        }

        void OnLaunch(object sender, EventArgs e) {
            string launcher = LauncherExe;
            if (!File.Exists(launcher)) {
                MessageBox.Show(this, "launcher.exe not found at: " + launcher,
                                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (string.IsNullOrEmpty(tbOutput.Text) || !File.Exists(tbOutput.Text)) {
                MessageBox.Show(this, "Generate the .bin first.",
                                "Missing", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            try {
                var psi = new ProcessStartInfo(launcher, Quote(tbOutput.Text)) {
                    UseShellExecute = false
                };
                Process.Start(psi);
                Log("launched " + Path.GetFileName(tbOutput.Text));
            } catch (Exception ex) {
                Log("[exception] " + ex.Message);
            }
        }

        [STAThread]
        static void Main() {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
