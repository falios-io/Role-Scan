using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace RoleScan
{
    public class Authority
    {
        public string AuthorityHostUri { get => "https://login.microsoftonline.com"; }
        public string TenantId { get; private set; }
        public string AuthorityUri { get => AuthorityHostUri + '/' + TenantId; }
        public string ResourceUri { get => "https://management.core.windows.net/"; }
        public string ClientId { get; private set; }
        public string Secret { get; private set; }

        public ClientCredential ClientCredential { get; private set; }

        private Authority() {}

        public Authority(string tenantId) {
            this.TenantId = tenantId;
            this.ClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
        }

        public Authority(string tenantId, string clientId, string secret) {
            this.TenantId = tenantId;
            this.ClientId = clientId;
            this.Secret = secret;
            this.ClientCredential = new ClientCredential(clientId, secret);
        }
    }
}