using System;
using CommandLine;

namespace RoleScan
{
    public class Options
    {
        private bool _builtin = false;
        private bool _custom = true;

        [Option('t', "tenant", Required = true, HelpText = "The Id of your Azure tenant.")]
        public string Tenant { get; set; }

        [Option('c', "client", Required = false, HelpText = "The client (application) Id. Required to execute under a Service Principal.")]
        public string Client { get; set; }

        [Option('s', "secret", Required = false, HelpText = "The client secret. Required to execute under a Service Principal.")]
        public string Secret { get; set; }

        [Option('b', "builtin", Required = false, HelpText = "Include built-in roles. (Default: false)")]
        public bool Builtin 
        {
            get => _builtin;
            set => _builtin = value;
        }

        [Option('i', "ignore-custom", Required = false, HelpText = "Ignore custom roles. (Default: false)")]
        public bool Custom 
        {
            get => _custom;
            set => _custom = !value;
        }

        [Option('d', "delete", Required = false, HelpText = "By default, the scan only performs a soft scan.  Specify this option to perform deletion.")]
        public bool Delete { get; set; }
    }
}