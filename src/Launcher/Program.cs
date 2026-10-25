using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace NpsBypassSync
{
    /// <summary>
    /// Starts Start-NpsBypassSync.ps1 inside an in-process Windows PowerShell 5.1 runspace.
    /// The script and its assets travel inside this exe, so it runs from anywhere without an install,
    /// without execution-policy prompts and without a console window.
    /// </summary>
    internal static class Program
    {
        private static readonly string WorkRoot = Path.Combine(Path.GetTempPath(), "NpsBypassSync");
        private static readonly string LogFile = Path.Combine(WorkRoot, "launcher.log");

        [STAThread]
        private static int Main(string[] args)
        {
            var arguments = ParseArguments(args);
            bool headless = new[] { "Sync", "Preview", "EnableAutoSync", "DisableAutoSync" }.Any(arguments.ContainsKey);
            Splash splash = headless ? null : Splash.ShowAsync();
            string appDir = null;
            int exitCode = 0;

            try
            {
                Directory.CreateDirectory(WorkRoot);
                Log("Starting " + Assembly.GetExecutingAssembly().GetName().Version + " from " + Application.ExecutablePath);
                CleanOldRuns();
                RemoveOldExe();
                appDir = ExtractPayload();

                string script = File.ReadAllText(Path.Combine(appDir, "Start-NpsBypassSync.ps1"), Encoding.UTF8);
                var state = InitialSessionState.CreateDefault();
                state.ExecutionPolicy = Microsoft.PowerShell.ExecutionPolicy.Bypass;
                state.ApartmentState = ApartmentState.STA;
                state.ThreadOptions = PSThreadOptions.UseCurrentThread;

                using (var runspace = RunspaceFactory.CreateRunspace(state))
                {
                    runspace.Open();
                    using (var ps = PowerShell.Create())
                    {
                        ps.Runspace = runspace;
                        ps.AddScript(script)
                          .AddParameter("AppRoot", appDir)
                          .AddParameter("LauncherDir", Path.GetDirectoryName(Application.ExecutablePath))
                          .AddParameter("OnReady", (Action)(() => splash?.Close()))
                          .AddParameter("ToolVersion", ToolVersion())
                          .AddParameter("LauncherPath", Application.ExecutablePath);
                        foreach (var pair in arguments) ps.AddParameter(pair.Key, pair.Value);

                        ps.Streams.Information.DataAdded += (s, e) => Log(ps.Streams.Information[e.Index].ToString());
                        ps.Streams.Warning.DataAdded += (s, e) => Log("WARNING: " + ps.Streams.Warning[e.Index]);
                        ps.Streams.Error.DataAdded += (s, e) => Log("ERROR: " + ps.Streams.Error[e.Index]);

                        ps.Invoke();
                        if (headless && ps.HadErrors) exitCode = 1;
                    }
                }
            }
            catch (Exception ex)
            {
                exitCode = 1;
                var root = ex is RuntimeException rte && rte.ErrorRecord != null ? rte.ErrorRecord.Exception : ex;
                Log("FATAL: " + ex);
                splash?.Close();
                if (!headless)
                {
                    MessageBox.Show(
                        "NPS Bypass Sync could not start:\n\n" + root.Message + "\n\nDetails: " + LogFile,
                        "NPS Bypass Sync", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            finally
            {
                splash?.Close();
                TryDelete(appDir);
            }
            return exitCode;
        }

        /// <summary>Turns "-Name value -Switch" into PowerShell parameters.</summary>
        private static Dictionary<string, object> ParseArguments(string[] args)
        {
            var result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (!(a.StartsWith("-") || a.StartsWith("/")) || a.Length < 2) continue;
                string name = a.TrimStart('-', '/');
                if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    result[name] = args[++i];
                else
                    result[name] = true;
            }
            return result;
        }

        /// <summary>Version from the build (e.g. 1.0.0 or 1.0.0-ci.5), used by the update button.</summary>
        private static string ToolVersion()
        {
            var info = Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(AssemblyInformationalVersionAttribute), false)
                .OfType<AssemblyInformationalVersionAttribute>().FirstOrDefault();
            string v = info?.InformationalVersion ?? Assembly.GetExecutingAssembly().GetName().Version.ToString();
            int plus = v.IndexOf('+');
            return plus > 0 ? v.Substring(0, plus) : v;
        }

        /// <summary>After an update the previous exe is left as NpsBypassSync.exe.old; remove it once it is no longer running.</summary>
        private static void RemoveOldExe()
        {
            try
            {
                string old = Application.ExecutablePath + ".old";
                for (int i = 0; i < 10 && File.Exists(old); i++)
                {
                    try { File.Delete(old); }
                    catch { Thread.Sleep(500); }
                }
            }
            catch { }
        }

        private static string ExtractPayload()
        {
            string dir = Path.Combine(WorkRoot, "run-" + Guid.NewGuid().ToString("N").Substring(0, 10));
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip"))
            {
                if (stream == null) throw new InvalidOperationException("This build has no payload. Build it with build/Build.ps1.");
                using (var zip = new ZipArchive(stream, ZipArchiveMode.Read))
                {
                    zip.ExtractToDirectory(dir);
                }
            }
            return dir;
        }

        private static void CleanOldRuns()
        {
            try
            {
                foreach (var d in Directory.GetDirectories(WorkRoot, "run-*"))
                {
                    if (Directory.GetLastWriteTimeUtc(d) < DateTime.UtcNow.AddHours(-12)) TryDelete(d);
                }
                var log = new FileInfo(LogFile);
                if (log.Exists && log.Length > 2 * 1024 * 1024) log.Delete();
            }
            catch { }
        }

        private static void TryDelete(string dir)
        {
            if (string.IsNullOrEmpty(dir)) return;
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
        }

        private static void Log(string message)
        {
            try { File.AppendAllText(LogFile, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + message + Environment.NewLine); } catch { }
        }
    }

    /// <summary>Small splash window on its own UI thread, so the user sees something instantly.</summary>
    internal sealed class Splash : Form
    {
        private readonly ManualResetEventSlim _shown = new ManualResetEventSlim();
        private int _closed;

        public static Splash ShowAsync()
        {
            Splash splash = null;
            var created = new ManualResetEventSlim();
            var thread = new Thread(() =>
            {
                splash = new Splash();
                created.Set();
                Application.Run(splash);
            });
            thread.SetApartmentState(ApartmentState.STA);
            thread.IsBackground = true;
            thread.Start();
            created.Wait();
            return splash;
        }

        private Splash()
        {
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.CenterScreen;
            ShowInTaskbar = true;
            TopMost = true;
            BackColor = Color.White;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            ClientSize = new Size(420, 210);
            Text = "NPS Bypass Sync";
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            Shown += (s, e) => _shown.Set();
            Paint += (s, e) => e.Graphics.DrawRectangle(new Pen(Color.FromArgb(0xE5, 0xE5, 0xE5)), 0, 0, ClientSize.Width - 1, ClientSize.Height - 1);

            var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("splash-logo.png");
            if (stream != null)
            {
                var logo = Image.FromStream(stream);
                int h = 40, w = logo.Width * h / logo.Height;
                Controls.Add(new PictureBox { Image = logo, SizeMode = PictureBoxSizeMode.Zoom, Size = new Size(w, h), Location = new Point((420 - w) / 2, 40) });
            }
            Controls.Add(new Label
            {
                Text = "NPS Bypass Sync is starting...",
                Font = new Font("Segoe UI", 11F),
                ForeColor = Color.FromArgb(0x1B, 0x1B, 0x1B),
                TextAlign = ContentAlignment.MiddleCenter,
                Size = new Size(420, 30),
                Location = new Point(0, 112),
            });
            Controls.Add(new ProgressBar { Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 25, Size = new Size(260, 6), Location = new Point(80, 158) });
        }

        public new void Close()
        {
            if (Interlocked.Exchange(ref _closed, 1) == 1) return;
            _shown.Wait(5000);
            try { BeginInvoke((Action)(() => base.Close())); } catch { }
        }
    }
}
