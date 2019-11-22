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
using Microsoft.Rest.Azure;
using System.Collections.Generic;
using Microsoft.Azure.Graph.RBAC.Models;

namespace RoleScan
{
    class Program
    {
        private static readonly ConsoleColor DEFAULTFOREGROUND = Console.ForegroundColor;
        private static Options _options;
        private static ServiceClientCredentials _serviceCreds;
        private static ServiceClientCredentials _graphCreds;
        static async Task Main(string[] args)
        {
            try
            {
                Parser.Default.ParseArguments<Options>(args)
                    .WithParsed<Options>(o =>
                    {
                        _options = o;
                    });

                if (_options != null)
                {
                    if (!string.IsNullOrWhiteSpace(_options.Client) && !string.IsNullOrWhiteSpace(_options.Secret))
                        (_serviceCreds, _graphCreds) = await AuthenticateClientKey(_options.Tenant, _options.Client, _options.Secret);
                    else
                        (_serviceCreds, _graphCreds) = await AuthenticateDeviceCode(_options.Tenant);

                    if (!_options.Delete)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.Write("INFO:");

                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine(" Argument '-d, --delete' is missing. Actual deletion of definitions will be skipped.\n");
                    }

                    GetSubscriptions();
                }
            }
            finally
            {
                Console.ForegroundColor = DEFAULTFOREGROUND;
            }
        }

        private static async Task<(TokenCredentials, TokenCredentials)> AuthenticateDeviceCode(string tenantId)
        {
            var authority = new Authority(tenantId);
            var context = new AuthenticationContext(authority.AuthorityUri);
            var code = await context.AcquireDeviceCodeAsync(authority.ResourceUri, authority.ClientId);
            Console.WriteLine("\n" + code.Message + "\n\n");

            AuthenticationResult token = await context.AcquireTokenByDeviceCodeAsync(code);

            var serviceCredentials = new TokenCredentials(token.AccessToken);

            var silentToken = await context.AcquireTokenSilentAsync(authority.GraphUri, authority.ClientId, new UserIdentifier(token.UserInfo.UniqueId, UserIdentifierType.UniqueId));
            var graphCredentials = new TokenCredentials(silentToken.AccessToken);

            return (serviceCredentials, graphCredentials);
        }

        private static async Task<(TokenCredentials, TokenCredentials)> AuthenticateClientKey(string tenantId, string clientId, string secret)
        {
            var authority = new Authority(tenantId, clientId, secret);
            var context = new AuthenticationContext(authority.AuthorityUri);

            AuthenticationResult token = await context.AcquireTokenAsync(authority.ResourceUri, authority.ClientCredential);

            var serviceCredentials = new TokenCredentials(token.AccessToken);

            var silentToken = await context.AcquireTokenSilentAsync(authority.GraphUri, authority.ClientId, new UserIdentifier(token.UserInfo.UniqueId, UserIdentifierType.UniqueId));
            var graphCredentials = new TokenCredentials(silentToken.AccessToken);

            return (serviceCredentials, graphCredentials);
        }

        public static void GetSubscriptions()
        {
            var subClient = new SubscriptionClient(_serviceCreds);

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"Subscriptions:");

            var subs = subClient.Subscriptions.List();

            foreach (var sub in subs)
            {

                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"   {sub.DisplayName} ");

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"({sub.SubscriptionId})");

                GetRoles(sub.Id);

                Console.WriteLine();
            }
        }

        public static void GetRoles(string subId)
        {
            AuthorizationManagementClient client = new AuthorizationManagementClient(_serviceCreds);

            IPage<RoleDefinition> defs = null;

            if (_options.Custom && !_options.Builtin)
                defs = client.RoleDefinitions.List(subId, new ODataQuery<RoleDefinitionFilter>(r => r.Type == "CustomRole"));
            else if (_options.Builtin && !_options.Custom)
                defs = client.RoleDefinitions.List(subId, new ODataQuery<RoleDefinitionFilter>(r => r.Type == "BuiltinRole"));
            else if (_options.Builtin && _options.Custom)
                defs = client.RoleDefinitions.List(subId);

            if (defs != null)
            {
                foreach (var def in defs)
                {
                    IEnumerable<RoleAssignment> assignees = client.RoleAssignments.ListForScope(subId).Where(r => r.RoleDefinitionId == def.Id);

                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write($"    - {def.RoleName} ");

                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write($"({def.Name})");

                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write($"... ");

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write($"Role Assignments: ");

                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write($"{assignees.Count()}");

                    if (assignees.Any())
                    {
                        ShowMembers(assignees);
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.Write($"   Deleting...");

                        Console.ForegroundColor = ConsoleColor.White;

                        if (_options.Delete && def.Type == "CustomRole")
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

        public static void ShowMembers(IEnumerable<RoleAssignment> assignees)
        {
            foreach (var member in assignees)
            {
                Console.WriteLine();

                Console.ForegroundColor = ConsoleColor.White;
                try
                {
                    if (member.PrincipalType == "ServicePrincipal")
                    {
                        var service = GetServicePrincipal(member.PrincipalId);
                        Console.Write($"        - {service.DisplayName} <ServicePrincipal> ");
                    }
                    else if (member.PrincipalType == "Application")
                    {
                        var service = GetApplication(member.PrincipalId);
                        Console.Write($"        - {service.DisplayName} <Application> ");
                    }
                    else if (member.PrincipalType == "DirectoryObjectOrGroup")
                    {
                        var service = GetDirectoryObject(member.PrincipalId);
                        Console.Write($"        - {service.DisplayName} <Directory Object or Group> ");
                    }
                    else if (member.PrincipalType == "User")
                    {
                        var user = GetUser(member.PrincipalId);
                        Console.Write($"        - {user.DisplayName} <{user.UserPrincipalName}> ");
                    }
                    else
                    {
                        Console.Write($"        - Unknown Principal ");
                    }
                }
                catch
                {
                    Console.Write($"        - Graph Error ");
                }

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"({member.PrincipalId})");

                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine($"... ");

                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.Write($"          Scope: ");

                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"{member.Scope}");
            }
        }

        public static User GetUser(string principalId)
        {
            GraphRbacManagementClient graphClient = new GraphRbacManagementClient(_graphCreds);
            graphClient.TenantID = _options.Tenant;

            return graphClient.Users.GetAsync(principalId).Result;
        }

        public static ServicePrincipal GetServicePrincipal(string principalId)
        {
            GraphRbacManagementClient graphClient = new GraphRbacManagementClient(_graphCreds);
            graphClient.TenantID = _options.Tenant;

            return graphClient.ServicePrincipals.GetAsync(principalId).Result;
        }

        public static Application GetApplication(string principalId)
        {
            GraphRbacManagementClient graphClient = new GraphRbacManagementClient(_graphCreds);
            graphClient.TenantID = _options.Tenant;

            return graphClient.Applications.GetAsync(principalId).Result;
        }

        public static ADGroup GetDirectoryObject(string principalId)
        {
            GraphRbacManagementClient graphClient = new GraphRbacManagementClient(_graphCreds);
            graphClient.TenantID = _options.Tenant;

            return graphClient.Groups.GetAsync(principalId).Result;
        }
    }
}
