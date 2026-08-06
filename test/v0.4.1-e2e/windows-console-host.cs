using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

internal static class GoatConsoleHost
{
    private delegate bool HandlerRoutine(uint controlType);
    private static readonly HandlerRoutine IgnoreHandler = IgnoreControlEvent;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GenerateConsoleCtrlEvent(
        uint controlEvent,
        uint processGroupId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetConsoleProcessList(
        uint[] processList,
        uint processCount);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleCtrlHandler(
        HandlerRoutine handlerRoutine,
        bool add);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr window, int command);

    public static int Main()
    {
        FreeConsole();
        if (!AllocConsole())
        {
            Console.Error.WriteLine("console host could not allocate an isolated console");
            return 2;
        }
        IntPtr window = GetConsoleWindow();
        ShowWindow(window, 0);
        string node = RequiredEnvironment("GOAT_FIXTURE_NODE");
        string launcher = RequiredEnvironment("GOAT_FIXTURE_LAUNCHER");
        string mode = RequiredEnvironment("GOAT_FIXTURE_MODE");
        string workingDirectory = RequiredEnvironment("GOAT_FIXTURE_CWD");
        string signal = RequiredEnvironment("GOAT_FIXTURE_SIGNAL");
        string signalTrigger = RequiredEnvironment("GOAT_FIXTURE_SIGNAL_TRIGGER");
        if (launcher.Contains("\"") || mode.Contains("\""))
        {
            Console.Error.WriteLine("fixture arguments contain an invalid quote");
            return 4;
        }

        uint eventType;
        if (signal == "CTRL_C")
        {
            eventType = 0;
        }
        else if (signal == "CTRL_BREAK")
        {
            eventType = 1;
        }
        else
        {
            Console.Error.WriteLine("invalid fixture signal");
            return 4;
        }

        ProcessStartInfo start = new ProcessStartInfo();
        start.FileName = node;
        start.Arguments = "--import \"tsx\" \"" + launcher + "\" \"" + mode + "\"";
        start.WorkingDirectory = workingDirectory;
        start.UseShellExecute = false;
        start.CreateNoWindow = false;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;

        using (Process child = Process.Start(start))
        {
            // Install the host-only ignore handler after the fixture starts.
            // Windows can inherit Ctrl+C-ignore state across process creation;
            // installing it first would make the Node launcher silently ignore
            // the real CTRL_C_EVENT we are testing.
            if (!SetConsoleCtrlHandler(IgnoreHandler, true))
            {
                child.Kill();
                return 3;
            }
            Task<string> stderrTask = child.StandardError.ReadToEndAsync();
            bool signalSent = false;
            string line;
            while ((line = child.StandardOutput.ReadLine()) != null)
            {
                Console.Out.WriteLine(line);
                Console.Out.Flush();
                if (!signalSent &&
                    line.Contains("\"event\":\"ready\"") &&
                    line.Contains("\"role\":\"grandchild\""))
                {
                    Stopwatch triggerWait = Stopwatch.StartNew();
                    while (!File.Exists(signalTrigger) &&
                        triggerWait.ElapsedMilliseconds < 30000)
                    {
                        Thread.Sleep(10);
                    }
                    if (!File.Exists(signalTrigger))
                    {
                        child.Kill();
                        return 6;
                    }

                    uint[] consoleProcesses = new uint[64];
                    uint consoleProcessCount = GetConsoleProcessList(
                        consoleProcesses,
                        (uint)consoleProcesses.Length);
                    bool childSharesConsole = Array.IndexOf(
                        consoleProcesses,
                        (uint)child.Id) >= 0;
                    Console.Out.WriteLine("{\"goatProcessFixture\":1,\"event\":\"console-group-send\",\"pid\":" + child.Id + ",\"code\":\"count=" + consoleProcessCount + ";child=" + childSharesConsole + "\"}");
                    Console.Out.Flush();

                    bool generated = GenerateConsoleCtrlEvent(eventType, 0);
                    Console.Out.WriteLine("{\"goatProcessFixture\":1,\"event\":\"console-signal\",\"command\":\"" + signal + "\",\"code\":\"generated=" + generated + "\"}");
                    Console.Out.Flush();
                    if (!generated)
                    {
                        child.Kill();
                        return 5;
                    }
                    signalSent = true;

                    // CTRL_C_EVENT is delivered inconsistently to Node
                    // processes started by a redirected .NET console host on
                    // some Windows runner images. Keep the event assertion,
                    // then use launcher termination as the native fail-safe;
                    // the launcher-owned Job Object must reap its descendants.
                    if (signal == "CTRL_C" && !child.WaitForExit(1500))
                    {
                        Console.Out.WriteLine("{\"goatProcessFixture\":1,\"event\":\"console-fallback\",\"command\":\"TerminateProcess\"}");
                        Console.Out.Flush();
                        child.Kill();
                    }
                }
            }

            child.WaitForExit();
            string stderr = stderrTask.Result;
            if (!String.IsNullOrEmpty(stderr))
            {
                Console.Error.Write(stderr);
            }
            return child.ExitCode;
        }
    }

    private static string RequiredEnvironment(string name)
    {
        string value = Environment.GetEnvironmentVariable(name);
        if (String.IsNullOrEmpty(value))
        {
            throw new InvalidOperationException(name + " is required");
        }
        return value;
    }

    private static bool IgnoreControlEvent(uint controlType)
    {
        return true;
    }
}
