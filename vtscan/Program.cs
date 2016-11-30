using Gnu.Getopt;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Reflection;
using VirusTotalNET;
using VirusTotalNET.Objects;

namespace VirusTotalNETClient
{
    class Program
    {
        private static string api_key = "api key here";

        static void Main(string[] args)
        {
            bool rescan = false;
            string file = null;
            string url = null;
            string progname = Path.GetFileName(Assembly.GetExecutingAssembly().CodeBase);

            Getopt opt = new Getopt(progname, args, "f:u:r");
            int c;
            while ((c = opt.getopt()) != -1)
            {
                switch (c)
                {
                    case 'f':
                        file = opt.Optarg;
                        break;
                    case 'u':
                        url = opt.Optarg;
                        break;
                    case 'r':
                        rescan = true;
                        break;
                    default:
                        return;
                }
            }

            if (file != null)
                FileScan(file, rescan);
            if(url != null)
                UrlScan(url);
        }

        private static void FileScan(string file, bool rescan)
        {
            try
            {
                VirusTotal virusTotal = new VirusTotal(api_key);
                virusTotal.UseTLS = true;
                FileInfo fileInfo = new FileInfo(file);
                FileReport fileReport = virusTotal.GetFileReport(fileInfo);
                bool hasFileBeenScannedBefore = fileReport.ResponseCode == ReportResponseCode.Present;
                Console.WriteLine("File has been scanned before: " + (hasFileBeenScannedBefore ? "Yes" : "No"));
                if (hasFileBeenScannedBefore)
                {
                    if(rescan)
                    {
                        ScanResult fileResult = virusTotal.RescanFile(fileInfo);
                        PrintScan(fileResult);
                    }
                    else
                    {
                        PrintScan(fileReport);
                    }
                }
                else
                {
                    ScanResult fileResult = virusTotal.ScanFile(fileInfo);
                    PrintScan(fileResult);
                }
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }        
        }

        private static void UrlScan(string url)
        {
            try
            {
                VirusTotal virusTotal = new VirusTotal(api_key);
                virusTotal.UseTLS = true;
                UrlReport urlReport = virusTotal.GetUrlReport(url);
                bool hasUrlBeenScannedBefore = urlReport.ResponseCode == ReportResponseCode.Present;
                Console.WriteLine("File has been scanned before: " + (hasUrlBeenScannedBefore ? "Yes" : "No"));
                if (hasUrlBeenScannedBefore)
                {
                    PrintScan(urlReport);
                }
                else
                {
                    ScanResult urlResult = virusTotal.ScanUrl(url);
                    PrintScan(urlResult);
                }
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }         
        }

        private static void PrintScan(ScanResult scanResult)
        {
            Console.WriteLine("Response code: " + scanResult.ResponseCode.ToString());
            Console.WriteLine("Scan ID: " + scanResult.ScanId);
            Console.WriteLine("Message: " + scanResult.VerboseMsg);
        }

        private static void PrintScan(FileReport fileReport)
        {
            Console.WriteLine("Response code: " + fileReport.ResponseCode.ToString());
            Console.WriteLine("Scan ID: " + fileReport.ScanId);
            Console.WriteLine("Message: " + fileReport.VerboseMsg);     
            Console.WriteLine("Last Scan Date: " + fileReport.ScanDate.ToString());
            Console.WriteLine("Detection Rate: " + fileReport.Positives.ToString() + " of " + fileReport.Total.ToString());
            Console.WriteLine("Permalink: " + fileReport.Permalink);
            if (fileReport.ResponseCode == ReportResponseCode.Present)
            {
                Console.WriteLine("{0,-22} {1,-30} {2}", "Antivirus", "Result", "Update");
                foreach (KeyValuePair<string, ScanEngine> scan in fileReport.Scans)
                {
                    Console.WriteLine("{0,-22} {1,-30} {2}", scan.Key, scan.Value.Result, scan.Value.UpdateDate.ToShortDateString());
                }
            }
        }

        private static void PrintScan(UrlReport urlReport)
        {
            Console.WriteLine("Response code: " + urlReport.ResponseCode.ToString());
            Console.WriteLine("Scan ID: " + urlReport.ScanId);
            Console.WriteLine("Message: " + urlReport.VerboseMsg);
            Console.WriteLine("Last Scan Date: " + urlReport.ScanDate.ToString());
            Console.WriteLine("Detection Rate: " + urlReport.Positives.ToString() + " of " + urlReport.Total.ToString());
            Console.WriteLine("Permalink: " + urlReport.Permalink);
            if (urlReport.ResponseCode == ReportResponseCode.Present)
            {
                Console.WriteLine("{0,-25} {1}", "URL Scanner", "Result");
                foreach (KeyValuePair<string, ScanEngine> scan in urlReport.Scans)
                {
                    Console.WriteLine("{0,-25} {1}", scan.Key, scan.Value.Result);
                }
            }
        }
    }
}