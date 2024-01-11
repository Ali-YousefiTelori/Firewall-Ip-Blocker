using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;

namespace Firewall_Ip_Blocker.WindowsConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("pls enter your firewall role name:");
            var roleName = Console.ReadLine();
            while (true)
            {
                try
                {
                    Console.WriteLine("Check new Ip to block!");
                    EventLog log = new EventLog("Security");
                    var entries = log.Entries.Cast<EventLogEntry>().Where(x => x.InstanceId == 4625).ToList();
                    List<string> IpAddresses = new List<string>();
                    foreach (var entry in entries)
                    {
                        if (entry.Message.Contains("An account failed to log on."))
                        {
                            var split = entry.Message.Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                            var find = split.FirstOrDefault(x => x.Contains("Source Network Address"));
                            var ip = find.Split(':')[1].Trim();
                            IpAddresses.Add(ip);
                        }
                    }
                    var roles = FirewallManager.Instance.Rules.Where(x => x.Name == roleName).ToList();
                    foreach (var role in roles)
                    {
                        var allBlockedIps = role.RemoteAddresses;
                        List<WindowsFirewallHelper.IAddress> blockedIps = new List<IAddress>();
                        blockedIps.AddRange(allBlockedIps);
                        Console.WriteLine($"Found {allBlockedIps.Length}");
                        foreach (var ip in IpAddresses)
                        {
                            if (!blockedIps.Any(x => ((SingleIP)x).ToString() == ip))
                            {
                                try
                                {
                                    if (ip == "-")
                                        continue;
                                    blockedIps.Add(new SingleIP(IPAddress.Parse(ip).GetAddressBytes()));
                                    Console.WriteLine($"New Ip Blocked {ip}");
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"Error on Ip: {ip} {ex}");
                                }
                            }
                        }
                        role.RemoteAddresses = blockedIps.ToArray();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                    break;
                }
                Console.WriteLine("Completed");
                Task.Delay(30000).Wait();
            }
            Console.WriteLine("done");
            Console.ReadLine();
        }
    }
}
