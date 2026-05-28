using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SteamOwnership
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            try
            {
                var options = CliOptions.Parse(args);
                var scanner = new SteamOwnedGamesScanner(options.SteamPath);
                var ownedAppIds = scanner.ScanOwnedAppIds(options.AppIds);
                Console.WriteLine(JsonPayload.Success(scanner.ResolvedSteamPath, options.AppIds.Count, ownedAppIds));
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine(JsonPayload.Error(ex.Message));
                return 1;
            }
        }
    }

    internal sealed class CliOptions
    {
        public string SteamPath { get; private set; }
        public List<uint> AppIds { get; } = new List<uint>();

        public static CliOptions Parse(string[] args)
        {
            if (args == null || args.Length == 0)
            {
                throw new InvalidOperationException("Steam ownership helper requires --steam-path and --appid-file arguments.");
            }

            var options = new CliOptions();
            for (var index = 0; index < args.Length; index++)
            {
                var arg = args[index] ?? string.Empty;
                if (string.Equals(arg, "--steam-path", StringComparison.OrdinalIgnoreCase))
                {
                    options.SteamPath = ReadValue(args, ref index, "--steam-path");
                    continue;
                }

                if (string.Equals(arg, "--appid-file", StringComparison.OrdinalIgnoreCase))
                {
                    var path = ReadValue(args, ref index, "--appid-file");
                    options.LoadAppIds(path);
                    continue;
                }
            }

            if (string.IsNullOrWhiteSpace(options.SteamPath))
            {
                throw new InvalidOperationException("Steam install path was not provided to the ownership helper.");
            }

            if (options.AppIds.Count == 0)
            {
                throw new InvalidOperationException("No Steam app IDs were provided to the ownership helper.");
            }

            return options;
        }

        private static string ReadValue(string[] args, ref int index, string optionName)
        {
            if (index + 1 >= args.Length)
            {
                throw new InvalidOperationException(optionName + " is missing its value.");
            }

            index += 1;
            return args[index] ?? string.Empty;
        }

        private void LoadAppIds(string appIdFile)
        {
            if (!File.Exists(appIdFile))
            {
                throw new FileNotFoundException("Steam app ID file was not found.", appIdFile);
            }

            var seen = new HashSet<uint>();
            foreach (var rawLine in File.ReadAllLines(appIdFile))
            {
                var line = (rawLine ?? string.Empty).Trim();
                if (line.Length == 0)
                {
                    continue;
                }

                uint parsed;
                if (!uint.TryParse(line, out parsed) || parsed == 0)
                {
                    continue;
                }

                if (seen.Add(parsed))
                {
                    AppIds.Add(parsed);
                }
            }
        }
    }

    internal sealed class SteamOwnedGamesScanner
    {
        private readonly string _steamPath;

        public string ResolvedSteamPath => _steamPath;

        public SteamOwnedGamesScanner(string steamPath)
        {
            _steamPath = ResolveSteamPath(steamPath);
        }

        public List<uint> ScanOwnedAppIds(IEnumerable<uint> candidateAppIds)
        {
            NativeMethods.SetDllDirectory(_steamPath);

            var steamClientDll = Path.Combine(_steamPath, "steamclient.dll");
            var module = NativeMethods.LoadLibrary(steamClientDll);
            if (module == IntPtr.Zero)
            {
                throw new InvalidOperationException("Could not load steamclient.dll from " + _steamPath + ".");
            }

            var createInterfacePtr = NativeMethods.GetProcAddress(module, "CreateInterface");
            if (createInterfacePtr == IntPtr.Zero)
            {
                throw new InvalidOperationException("Steam's CreateInterface export was not found.");
            }

            var createInterface = (CreateInterfaceDelegate)Marshal.GetDelegateForFunctionPointer(
                createInterfacePtr,
                typeof(CreateInterfaceDelegate)
            );

            var steamClientPtr = createInterface("SteamClient018", IntPtr.Zero);
            if (steamClientPtr == IntPtr.Zero)
            {
                throw new InvalidOperationException("Could not create the Steam client interface. Start Steam first.");
            }

            var clientVTable = Marshal.ReadIntPtr(steamClientPtr);
            var client = (SteamClientInterface)Marshal.PtrToStructure(clientVTable, typeof(SteamClientInterface));

            var createSteamPipe = (CreateSteamPipeDelegate)Marshal.GetDelegateForFunctionPointer(
                client.CreateSteamPipe,
                typeof(CreateSteamPipeDelegate)
            );
            var connectToGlobalUser = (ConnectToGlobalUserDelegate)Marshal.GetDelegateForFunctionPointer(
                client.ConnectToGlobalUser,
                typeof(ConnectToGlobalUserDelegate)
            );
            var releaseUser = (ReleaseUserDelegate)Marshal.GetDelegateForFunctionPointer(
                client.ReleaseUser,
                typeof(ReleaseUserDelegate)
            );
            var releaseSteamPipe = (ReleaseSteamPipeDelegate)Marshal.GetDelegateForFunctionPointer(
                client.ReleaseSteamPipe,
                typeof(ReleaseSteamPipeDelegate)
            );
            var getSteamApps = (GetSteamAppsDelegate)Marshal.GetDelegateForFunctionPointer(
                client.GetISteamApps,
                typeof(GetSteamAppsDelegate)
            );

            var pipeHandle = createSteamPipe(steamClientPtr);
            if (pipeHandle == 0)
            {
                throw new InvalidOperationException("Steam is installed, but its client pipe is not available. Start Steam first.");
            }

            var userHandle = connectToGlobalUser(steamClientPtr, pipeHandle);
            if (userHandle == 0)
            {
                releaseSteamPipe(steamClientPtr, pipeHandle);
                throw new InvalidOperationException("Steam is running, but no signed-in desktop account is available yet.");
            }

            var versionPtr = Marshal.StringToHGlobalAnsi("STEAMAPPS_INTERFACE_VERSION008");
            try
            {
                var steamAppsPtr = getSteamApps(steamClientPtr, userHandle, pipeHandle, versionPtr);
                if (steamAppsPtr == IntPtr.Zero)
                {
                    throw new InvalidOperationException("Could not access Steam's ownership interface for the running client.");
                }

                var appsVTable = Marshal.ReadIntPtr(steamAppsPtr);
                var apps = (SteamAppsInterface)Marshal.PtrToStructure(appsVTable, typeof(SteamAppsInterface));
                var isSubscribedApp = (IsSubscribedAppDelegate)Marshal.GetDelegateForFunctionPointer(
                    apps.IsSubscribedApp,
                    typeof(IsSubscribedAppDelegate)
                );

                var owned = new List<uint>();
                foreach (var appId in candidateAppIds)
                {
                    if (appId == 0)
                    {
                        continue;
                    }

                    if (isSubscribedApp(steamAppsPtr, appId))
                    {
                        owned.Add(appId);
                    }
                }

                return owned;
            }
            finally
            {
                Marshal.FreeHGlobal(versionPtr);
                releaseUser(steamClientPtr, pipeHandle, userHandle);
                releaseSteamPipe(steamClientPtr, pipeHandle);
            }
        }

        private static string ResolveSteamPath(string steamPath)
        {
            if (string.IsNullOrWhiteSpace(steamPath))
            {
                throw new InvalidOperationException("Steam install path is empty.");
            }

            var fullPath = Path.GetFullPath(steamPath.Trim());
            if (!Directory.Exists(fullPath))
            {
                throw new DirectoryNotFoundException("Steam install path was not found: " + fullPath);
            }

            var steamClientDll = Path.Combine(fullPath, "steamclient.dll");
            if (!File.Exists(steamClientDll))
            {
                throw new FileNotFoundException("steamclient.dll was not found in the Steam install path.", steamClientDll);
            }

            return fullPath;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SteamClientInterface
        {
            public IntPtr CreateSteamPipe;
            public IntPtr ReleaseSteamPipe;
            public IntPtr ConnectToGlobalUser;
            public IntPtr CreateLocalUser;
            public IntPtr ReleaseUser;
            public IntPtr GetISteamUser;
            public IntPtr GetISteamGameServer;
            public IntPtr SetLocalIPBinding;
            public IntPtr GetISteamFriends;
            public IntPtr GetISteamUtils;
            public IntPtr GetISteamMatchmaking;
            public IntPtr GetISteamMatchmakingServers;
            public IntPtr GetISteamGenericInterface;
            public IntPtr GetISteamUserStats;
            public IntPtr GetISteamGameServerStats;
            public IntPtr GetISteamApps;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SteamAppsInterface
        {
            public IntPtr IsSubscribed;
            public IntPtr IsLowViolence;
            public IntPtr IsCybercafe;
            public IntPtr IsVACBanned;
            public IntPtr GetCurrentGameLanguage;
            public IntPtr GetAvailableGameLanguages;
            public IntPtr IsSubscribedApp;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private delegate IntPtr CreateInterfaceDelegate(string version, IntPtr returnCode);

        [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
        private delegate int CreateSteamPipeDelegate(IntPtr self);

        [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
        private delegate bool ReleaseSteamPipeDelegate(IntPtr self, int pipeHandle);

        [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
        private delegate int ConnectToGlobalUserDelegate(IntPtr self, int pipeHandle);

        [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
        private delegate void ReleaseUserDelegate(IntPtr self, int pipeHandle, int userHandle);

        [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
        private delegate IntPtr GetSteamAppsDelegate(IntPtr self, int userHandle, int pipeHandle, IntPtr version);

        [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
        [return: MarshalAs(UnmanagedType.I1)]
        private delegate bool IsSubscribedAppDelegate(IntPtr self, uint appId);
    }

    internal static class JsonPayload
    {
        public static string Success(string steamPath, int checkedCount, List<uint> ownedAppIds)
        {
            var builder = new StringBuilder();
            builder.Append("{\"success\":true,\"steam_path\":\"");
            builder.Append(Escape(steamPath));
            builder.Append("\",\"checked\":");
            builder.Append(checkedCount);
            builder.Append(",\"owned_appids\":[");
            for (var index = 0; index < ownedAppIds.Count; index++)
            {
                if (index > 0)
                {
                    builder.Append(',');
                }

                builder.Append(ownedAppIds[index]);
            }

            builder.Append("]}");
            return builder.ToString();
        }

        public static string Error(string message)
        {
            return "{\"success\":false,\"error\":\"" + Escape(message) + "\"}";
        }

        private static string Escape(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            return value
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n");
        }
    }

    internal static class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetDllDirectory(string path);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibrary(string fileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr module, string procName);
    }
}
