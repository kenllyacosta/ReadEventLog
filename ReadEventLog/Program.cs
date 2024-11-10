using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace ReadEventLog
{
    internal class Program
    {
        static void Main(string[] args)
        {
            ReadWindowLogSecurity();
        }

        public static void ReadWindowLogSecurity()
        {
            //Read the Windows Log Security
            EventLog eventLog = new EventLog("Security");
            var entries = eventLog.Entries.Cast<EventLogEntry>().Where(x => x.InstanceId == 4625);
            foreach (var entry in entries)
            {
                if (entry.ReplacementStrings.Length >= 19)
                {
                    //Check if the IP is already blocked
                    List<string> blockedIps = ReadBlockedIps();

                    if (blockedIps.Contains(entry.ReplacementStrings[19]))
                        continue;

                    // Write to a log file the event
                    WriteToLogFile($"Event ID: {entry.InstanceId}, Time: {entry.TimeGenerated}, Strings: {string.Join(",", entry.ReplacementStrings)}");

                    AddIpToBlockedRuleFirewall(entry.ReplacementStrings[19]);
                }
            }
        }

        private static void AddIpToBlockedRuleFirewall(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
            {
                WriteToLogFile($"Invalid IP address. {ipAddress}");
                return;
            }

            try
            {
                // Create a process to run netsh command
                Process process = new Process();
                process.StartInfo.FileName = "netsh";
                process.StartInfo.Arguments = $"advfirewall firewall add rule name=\"Block {ipAddress}\" dir=in action=block remoteip={ipAddress}";
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    WriteToLogFile($"Successfully added firewall rule to block IP: {ipAddress}");

                    //Write the ip to a log file
                    WriteIpToLogFile(ipAddress);
                }
                else
                {
                    WriteToLogFile($"Failed to add firewall rule. Error: {error}");
                }
            }
            catch (Exception ex)
            {
                WriteToLogFile($"Exception occurred while adding firewall rule: {ex.Message}");
            }
        }

        private static void WriteToLogFile(string message)
        {
            //Write to a log file
            using (System.IO.StreamWriter file = new System.IO.StreamWriter("log.txt", true))
                file.WriteLine(message);
        }

        private static void WriteIpToLogFile(string ipAddress)
        {
            //Write to a log file
            using (System.IO.StreamWriter file = new System.IO.StreamWriter("blocked-ips.txt", true))
                file.WriteLine(ipAddress);
        }

        private static List<string> ReadBlockedIps()
        {
            //Read the list of blocked IPs from a file
            List<string> blockedIps = new List<string>();
            if (System.IO.File.Exists("blocked-ips.txt"))
                blockedIps = System.IO.File.ReadAllLines("blocked-ips.txt").ToList();

            return blockedIps;
        }
    }
}