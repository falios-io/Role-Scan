using System;
using System.Linq;
using Microsoft.Rest;
using Microsoft.Azure.Management.Authorization;
using Microsoft.Azure.Management.Authorization.Models;
using Microsoft.Azure.Management.Subscription;
using Microsoft.Azure.Graph.RBAC;
using Microsoft.Rest.Azure.OData;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Threading.Tasks;
using CommandLine;

namespace RoleScan
{
    class Program
    {
        private static readonly ConsoleColor DEFAULTFOREGROUND = Console.ForegroundColor;

        static async Task Main(string[] args)
        {
            try
            {
                Options options = null;

                Parser.Default.ParseArguments<Options>(args)
                    .WithParsed<Options>(o =>
                    {
                        options = o;
                    });

                if (options != null)
                {
                    TokenCredentials creds;

                    if (!string.IsNullOrWhiteSpace(options.Client) && !string.IsNullOrWhiteSpace(options.Secret))
                        creds = await AuthenticateClientKey(options.Tenant, options.Client, options.Secret);
                    else
                        creds = await AuthenticateDeviceCode(options.Tenant);

                    if (!options.Delete) {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.Write("INFO:");
                        
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine(" Argument '-d, --delete' is missing. Actual deletion of definitions will be skipped.\n");
                    }

                    GetSubscriptions(creds, options.Delete);
                }
            }
            finally
            {
                Console.ForegroundColor = DEFAULTFOREGROUND;
            }
        }

        private static async Task<TokenCredentials> AuthenticateDeviceCode(string tenantId)
        {
            var authority = new Authority(tenantId);
            var context = new AuthenticationContext(authority.AuthorityUri);
            var code = await context.AcquireDeviceCodeAsync(authority.ResourceUri, authority.ClientId);

            Console.WriteLine("\n" + code.Message + "\n\n");

            AuthenticationResult token = await context.AcquireTokenByDeviceCodeAsync(code);

            var credentials = new TokenCredentials(token.AccessToken);

            return credentials;
        }

        private static async Task<TokenCredentials> AuthenticateClientKey(string tenantId, string clientId, string secret)
        {
            var authority = new Authority(tenantId, clientId, secret);
            var context = new AuthenticationContext(authority.AuthorityUri);

            AuthenticationResult token = await context.AcquireTokenAsync(authority.ResourceUri, authority.ClientCredential);

            var credentials = new TokenCredentials(token.AccessToken);

            return credentials;
        }

        public static void GetSubscriptions(ServiceClientCredentials creds, bool delete)
        {
            var subClient = new SubscriptionClient(creds);

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"Subscriptions:");

            var subs = subClient.Subscriptions.List();

            foreach (var sub in subs)
            {

                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"   {sub.DisplayName} ");

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"({sub.SubscriptionId})");

                GetRoles(creds, sub.Id, delete);

                Console.WriteLine();
            }
        }

        public static void GetRoles(ServiceClientCredentials creds, string subId, bool delete)
        {
            AuthorizationManagementClient client = new AuthorizationManagementClient(creds);

            var defs = client.RoleDefinitions.List(subId, new ODataQuery<RoleDefinitionFilter>(r => r.Type == "CustomRole"));

            foreach (var def in defs)
            {
                var assigns = client.RoleAssignments.ListForScope(subId).Where(r => r.RoleDefinitionId == def.Id);

                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"    - {def.RoleName} ");

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"({def.Name})");

                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"... ");

                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"Role Assignments: ");

                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"{assigns.Count()}");

                if (!assigns.Any())
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write($"   Deleting...");

                    Console.ForegroundColor = ConsoleColor.White;

                    if (delete)
                    {
                        client.RoleDefinitions.Delete(subId, def.Name);
                        Console.Write("Done.");
                    }
                    else
                    {
                        Console.Write("Skipped.");
                    }
                }

                Console.WriteLine();
            }
        }
    }
}
