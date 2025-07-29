using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
    class Program
    {
        static string GetSnmpInfo(string ip, string community, string oid, string obj)
        {
            try
            {
                if (oid == "1.3.6.1.2.1.4.20.1.1" || oid == "1.3.6.1.2.1.25.3.3.1.2")
                {
                    var result = SnmpGetList(ip, community, oid);
                    Console.Write($"{obj} : ");
                    for (int i = 0; i < result.Count(); i++)
                    {
                        Console.Write($"{i + 1}: {result[i].Data} | ");
                    }
                    return null;
                }

                else
                {
                    var result = SnmpGet(ip, community, oid);
                    return $"{obj}\t : {result.Data}";
                }
            }
            catch (Exception ex)
            {
                return $"{obj}\t: нет информации | {ex.Message}";
            }
        }

        static List<Variable> SnmpGetList(string ip, string community, string oid)
        {
            var endpoint = new IPEndPoint(IPAddress.Parse(ip), 161);
            var result = new List<Variable>();
            Messenger.Walk(
                VersionCode.V1,
                endpoint,
                new OctetString(community),
                new ObjectIdentifier(oid),
                result,
                1000, WalkMode.WithinSubtree);
            return result;
        }

        static Variable SnmpGet(string ip, string community, string oid)
        {
            var endpoint = new IPEndPoint(IPAddress.Parse(ip), 161);
            try
            {
                var result = Messenger.Get(VersionCode.V2,
                    endpoint,
                    new OctetString(community),
                    new List<Variable> { new Variable(new ObjectIdentifier(oid)) },
                    1000);
                return result[0];
            }
            catch (Exception ex)
            {
                throw new Exception($"Ошибка | {ex}");
            }
        }

        static List<string> GetMacAddresses(string ip, string community)
        {
            var macList = new List<string>();
            var endpoint = new IPEndPoint(IPAddress.Parse(ip), 161);

            string macOid = "1.3.6.1.2.1.2.2.1.6";

            var results = new List<Variable>();
            Messenger.Walk(
                VersionCode.V2,
                endpoint,
                new OctetString(community),
                new ObjectIdentifier(macOid),
                results,
                3000,
                WalkMode.WithinSubtree);
            foreach (var variable in results)
            {
                if (variable.Data is OctetString octetString)
                {
                    byte[] macBytes = octetString.GetRaw();
                    if (macBytes.Length == 6)
                    {
                        string formattedMac = string.Join(":", macBytes.Select(b => b.ToString("X2")));
                        macList.Add(formattedMac);
                    }
                }
            }
            return macList;
        }

        static List<string> GetLocalNetworkIPs()// Получение IP адресов всех устройств в локальной сети
        {
            var localIPs = new List<string>();
            var host = Dns.GetHostEntry(Dns.GetHostName());
            var localIP = host.AddressList.FirstOrDefault(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

            if (localIP != null)
            {
                var subnet = localIP.GetSubnetMask();
                for (int i = 1; i < 255; i++)
                {
                    var ip = $"{localIP.GetSubnetPrefix()}.{i}";
                    localIPs.Add(ip);
                }
            }
            return localIPs;
        }

        static bool IsPingable(string ip)
        {
            try
            {
                using (var ping = new Ping())
                {
                    var reply = ping.Send(ip, 1000);
                    return reply.Status == IPStatus.Success;
                }
            }
            catch
            {
                return false;
            }
        }
        static void GetPCInfo(string ip, string community)
        {
            Console.WriteLine($"\t Основная информация ПК ({ip}):");
            var result = GetSnmpInfo(ip, community, "1.3.6.1.2.1.1.5.0", "Имя компьютера");
            Console.WriteLine(result);
            result = GetSnmpInfo(ip, community, "1.3.6.1.2.1.1.1.0", "Описание системы");
            Console.WriteLine(result);
            result = GetSnmpInfo(ip, community, "1.3.6.1.2.1.1.3.0", "Время работы");
            Console.WriteLine(result);
            result = GetSnmpInfo(ip, community, "1.3.6.1.2.1.4.20.1.1", "IP-адрес");
            Console.WriteLine(result);
            Console.Write("MAC адреса: ");
            var res = GetMacAddresses(ip, community);
            foreach (var i in res)
            {
                Console.Write($"{i} | ");
            }
            Console.WriteLine();
            result = GetSnmpInfo(ip, community, "1.3.6.1.2.1.25.3.3.1.2", "Загруженность логических процессоров");
            Console.WriteLine(result);
            result = GetSnmpInfo(ip, community, "1.3.6.1.2.1.25.2.2.0", "Объем памяти (KB)");
            Console.WriteLine(result);
            Console.WriteLine("========================================================");
        }
        static void GetPrinterInfo(string ip, string community)
        {
            Console.WriteLine($"\t Информация о принтере ({ip}):");
            for (int i = 1; i < 10; i++)
            {
                var resultmodel = GetSnmpInfo(ip, community, $"1.3.6.1.2.1.25.3.2.1.3.{i}", "Модель принтера");
                if (resultmodel.Contains("Microsoft"))
                {
                    continue;
                }
                else if (resultmodel.Contains("Unknown"))
                {
                    Console.WriteLine("Не найдены принтеры");
                    break;
                }
                else
                {
                    Console.WriteLine(resultmodel);
                    var result = GetSnmpInfo(ip, community, $"1.3.6.1.2.1.25.3.2.1.5.{i}", "Рабочее состояние");
                    Console.WriteLine(result);
                    result = GetSnmpInfo(ip, community, $"1.3.6.1.2.1.25.3.5.1.1.{i}", "Текущее состояние");
                    Console.WriteLine(result);
                    result = GetSnmpInfo(ip, community, $"1.3.6.1.2.1.25.3.5.1.2.{i}", "Обнаруженные ошибки");
                    Console.WriteLine(result);
                    result = GetSnmpInfo(ip, community, "1.3.6.1.2.1.43.11.1.1.9", "Уровень тонера");
                    Console.WriteLine(result);
                    Console.WriteLine("========================================================");
                }
            }

        }
        static void Main()
        {
            string community = "public";
            var localIPs = GetLocalNetworkIPs();
            foreach (var ip in localIPs)
            {
            Console.WriteLine($"Проверка {ip}");
                if (IsPingable(ip)) // Проверяем доступность IP
                {
                    // Определение устройства
                    var PCcheck = GetSnmpInfo(ip, community, "1.3.6.1.2.1.1.5.0", "Test PC");
                    if (!PCcheck.Contains("нет информации"))
                    {
                        GetPCInfo(ip, community);
                    }
                    var PrinterCheck = GetSnmpInfo(ip, community, "1.3.6.1.2.1.25.3.2.1.3.1", "Test printer");
                    if (!PrinterCheck.Contains("нет информации"))
                    {
                        GetPrinterInfo(ip, community);
                    }
                }
            }
            Console.ReadLine();
        }
    }

    public static class IPAddressExtensions
    {
        public static string GetSubnetPrefix(this IPAddress ipAddress)
        {
            var bytes = ipAddress.GetAddressBytes();
            return string.Join(".", bytes.Take(bytes.Length - 1));
        }

        public static IPAddress GetSubnetMask(this IPAddress ipAddress)
        {
            // Пример маски подсети для класса C
            return IPAddress.Parse("255.255.255.0");
        }
    }

