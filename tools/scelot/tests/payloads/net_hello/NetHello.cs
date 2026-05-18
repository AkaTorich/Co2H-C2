// .NET payload for scelot. Two entry points:
//   - Main: standard EXE entry (string[] args). Used when launched directly.
//   - Run:  ICLRRuntimeHost::ExecuteInDefaultAppDomain calls this with a
//           single string argument; signature must be `static int Run(string)`.
using System;
using System.IO;

namespace NetHello {
    class Program {
        static int Main(string[] args) {
            return Run(string.Join(" ", args));
        }

        public static int Run(string arg) {
            // Write to a log file too — output to console may not be visible
            // when launched via in-process CLR hosting from a non-console
            // host. The log gives unambiguous proof the CLR ran our code.
            string log = Path.Combine(Path.GetTempPath(), "scelot_nethello.txt");
            File.WriteAllText(log,
                "scelot .NET payload OK\r\n" +
                "arg: \"" + (arg ?? "") + "\"\r\n");
            Console.WriteLine("scelot .NET payload OK");
            Console.WriteLine("arg: \"" + (arg ?? "") + "\"");
            return 0;
        }
    }
}
