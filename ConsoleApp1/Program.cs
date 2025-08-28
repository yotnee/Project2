using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
    class Program
    {
    private static Dictionary<string, string> OidDescriptions = new Dictionary<string, string>
    {
        { "1.3.6.1.2.1.1.5.0", "Имя компьютера" },
        { "1.3.6.1.2.1.1.1.0", "Описание системы" },
        { "1.3.6.1.2.1.1.3.0", "Время работы" },
        { "1.3.6.1.2.1.4.20.1.1", "IP-адрес" },
        { "1.3.6.1.2.1.25.3.3.1.2", "Загруженность логических процессоров" },
        { "1.3.6.1.2.1.25.2.2.0", "Объем памяти (KB)" },
        { "1.3.6.1.2.1.25.3.2.1.3.", "Модель принтера" },
        { "1.3.6.1.2.1.25.3.2.1.5.", "Рабочее состояние" },
        { "1.3.6.1.2.1.25.3.5.1.1.", "Текущее состояние" },
        { "1.3.6.1.2.1.25.3.5.1.2.", "Обнаруженные ошибки" },
        { "1.3.6.1.2.1.43.11.1.1.9.1.1", "Уровень тонера" }
    };
    static string GetSnmpInfo(string ip, string community, string oid)
        {
        string obj = "Неизвестный OID";
        if (OidDescriptions.ContainsKey(oid))
        {
            obj = OidDescriptions[oid];
        }
        else
        {
            foreach (var kvp in OidDescriptions)
            {
                if (kvp.Key.EndsWith(".") && oid.StartsWith(kvp.Key))
                {
                    obj = kvp.Value;
                    break;
                }
            }
        }
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
        try
        { 
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
        catch (Lextm.SharpSnmpLib.Messaging.TimeoutException e)
        {
            try
            {
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
            catch (Exception e2)
            {
                throw new Exception($"Ошибка | {e2}");
            }
        }
        catch (Exception ex)
        {
            throw new Exception($"Ошибка | {ex}");
        }
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
            catch (Lextm.SharpSnmpLib.Messaging.TimeoutException e)
        {
            try
            {
                var result = Messenger.Get(VersionCode.V1,
                    endpoint,
                    new OctetString(community),
                    new List<Variable> { new Variable(new ObjectIdentifier(oid)) },
                    1000);
                return result[0];
            }
            catch(Exception e2)
            {
                throw new Exception($"Ошибка | {e2}");
            }
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
        try
        {
            Messenger.Walk(
                VersionCode.V1,
                endpoint,
                new OctetString(community),
                new ObjectIdentifier(macOid),
                results,
                3000,
                WalkMode.WithinSubtree);
        }
        catch (Lextm.SharpSnmpLib.Messaging.TimeoutException e)
        {
            try
            {
                Messenger.Walk(
                VersionCode.V2,
                endpoint,
                new OctetString(community),
                new ObjectIdentifier(macOid),
                results,
                3000,
                WalkMode.WithinSubtree);
            }
            catch (Exception e2)
            {
                throw new Exception($"Ошибка | {e2}");
            }
        }
        catch (Exception ex)
        {
            throw new Exception($"Ошибка | {ex}");
        }
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
    static void IncrementIp(ref uint x)
    {
        byte[] bytes = BitConverter.GetBytes(x);
        uint y = BitConverter.ToUInt32(new byte[] { bytes[3], bytes[2], bytes[1], bytes[0] }, 0);
        y++;
        bytes = BitConverter.GetBytes(y);
        x = BitConverter.ToUInt32(new byte[] { bytes[3], bytes[2], bytes[1], bytes[0] }, 0);
    }

    static int IpCompare(uint x, uint y)
    {
        if (x == y) return 0;

        byte[] bytes = BitConverter.GetBytes(x);
        uint xx = BitConverter.ToUInt32(new byte[] { bytes[3], bytes[2], bytes[1], bytes[0] }, 0);

        bytes = BitConverter.GetBytes(y);
        uint yy = BitConverter.ToUInt32(new byte[] { bytes[3], bytes[2], bytes[1], bytes[0] }, 0);

        if (xx < yy) return -1;
        else return 1;
    }
    static List<string> GetLocalNetworkIPs() // Получение IP адресов всех устройств в локальной сети
    {
        var localIPs = new List<string>();
        var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

        foreach (var networkInterface in networkInterfaces)
        {
            if (networkInterface.OperationalStatus == OperationalStatus.Up &&
                networkInterface.Supports(NetworkInterfaceComponent.IPv4))
            {
                var ipProperties = networkInterface.GetIPProperties();
                foreach (var unicast in ipProperties.UnicastAddresses)
                {
                    if ((unicast.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) && ((uint)unicast.Address.Address != (uint)IPAddress.Parse("127.0.0.1").Address))
                    {
                        var subnetMask = (uint)unicast.IPv4Mask.Address;
                        var subnetAddress = (uint)unicast.Address.Address;
                        var startAddress = subnetAddress & subnetMask;
                        var endAddress = (uint)(~subnetMask | startAddress);
                        // Генерация всех возможных IP-адресов в подсети
                        IncrementIp(ref startAddress);
                        for (uint i = startAddress; IpCompare(i, endAddress) < 0; IncrementIp(ref i))
                        {
                            IPAddress ip = new IPAddress((long)i);

                            localIPs.Add(ip.ToString());
                        }
                    }
                }
            }
        }
        return localIPs.Distinct().ToList(); // Удаляем дубликаты
    }


    static bool IsPingable(string ip)
        {
            try
            {
                using (var ping = new Ping())
                {
                    var reply = ping.Send(ip, 10);
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
            var result = GetSnmpInfo(ip, community, "1.3.6.1.2.1.1.5.0");
            Console.WriteLine(result);
            result = GetSnmpInfo(ip, community, "1.3.6.1.2.1.1.1.0");
            Console.WriteLine(result);
            result = GetSnmpInfo(ip, community, "1.3.6.1.2.1.1.3.0");
            Console.WriteLine(result);
            result = GetSnmpInfo(ip, community, "1.3.6.1.2.1.4.20.1.1");
            Console.WriteLine(result);
            Console.Write("MAC адреса: ");
            var res = GetMacAddresses(ip, community);
            foreach (var i in res)
            {
                Console.Write($"{i} | ");
            }
            Console.WriteLine();
            result = GetSnmpInfo(ip, community, "1.3.6.1.2.1.25.3.3.1.2");
            Console.WriteLine(result);
            result = GetSnmpInfo(ip, community, "1.3.6.1.2.1.25.2.2.0");
            Console.WriteLine(result);
            Console.WriteLine("========================================================");
        }
        static void GetPrinterInfo(string ip, string community)
        {
            Console.WriteLine($"\t Информация о принтере ({ip}):");
            for (int i = 1; i < 10; i++)
            {
                var resultmodel = GetSnmpInfo(ip, community, $"1.3.6.1.2.1.25.3.2.1.3.{i}");
                if (resultmodel.Contains("Microsoft") || resultmodel.Contains("нет информации"))
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
                    var result = GetSnmpInfo(ip, community, $"1.3.6.1.2.1.25.3.2.1.5.{i}");
                    Console.WriteLine(result);
                    result = GetSnmpInfo(ip, community, $"1.3.6.1.2.1.25.3.5.1.1.{i}");
                    Console.WriteLine(result);
                    result = GetSnmpInfo(ip, community, $"1.3.6.1.2.1.25.3.5.1.2.{i}");
                    Console.WriteLine(result);
                    result = GetSnmpInfo(ip, community, "1.3.6.1.2.1.43.11.1.1.9.1.1");
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
                    var PCcheck = GetSnmpInfo(ip, community, "1.3.6.1.2.1.1.5.0");
                    if (!PCcheck.Contains("нет информации"))
                    {
                        GetPCInfo(ip, community);
                    }
                    var PrinterCheck = GetSnmpInfo(ip, community, "1.3.6.1.2.1.25.3.2.1.3.1");
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
}

