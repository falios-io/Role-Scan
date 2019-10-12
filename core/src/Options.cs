using System;
using CommandLine;

namespace RoleScan
{
    public class Options
    {
        [Option('t', "tenant", Required = true, HelpText = "The Id of your Azure tenant.")]
        public string Tenant { get; set; }

        [Option('c', "client", Required = false, HelpText = "The client (application) Id. Required to execute under a Service Principal.")]
        public string Client { get; set; }

        [Option('s', "secret", Required = false, HelpText = "The client secret. Required to execute under a Service Principal.")]
        public string Secret { get; set; }

        [Option('d', "delete", Required = false, HelpText = "By default, the scan only performs a soft scan.  Specify this option to perform deletion.")]
        public bool Delete { get; set; }
    }
}