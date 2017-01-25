using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.AccountManagement;
using System.IdentityModel.Metadata;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.IdentityModel.Selectors;
using System.Net;

namespace SAMLGrantHandlerSampleApp
{
    class Program
    {

        static void  Main(string[] args)
        {
            // Creating a SAML assertion

            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor();
            descriptor.TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
            DateTime issueInstant = DateTime.UtcNow;
            descriptor.Lifetime = new Lifetime(issueInstant, issueInstant + new TimeSpan(8, 0, 0));

            // This will be the audience restriction - Should be the endpoint of IS token endpoint
            descriptor.AppliesToAddress = "https://localhost:9443/oauth2/token";

            // Set NameID in SAML assertion
            List<Claim> claims = new List<Claim>() {
                new Claim(ClaimTypes.NameIdentifier, new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).Identity.Name) };

            descriptor.Subject = new ClaimsIdentity(claims);
            descriptor.AddAuthenticationClaims("urn:oasis:names:tc:SAML:2.0:ac:classes:X509");

            // IdP ID - Should come from resident IdP ID configured in IS
            descriptor.TokenIssuerName = "localhost";

            //X509Certificate2 signingCert = GetCertificateByThumbprint(StoreName.My, StoreLocation.LocalMachine, "‎6b f8 e1 36 eb 36 d4 a5 6e a0 5c 7a e4 b9 a4 5b 63 bf 97 5d");

            // Get cert for signing from certificate store
            X509Store store = new X509Store(StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2 signingCert = store.Certificates[1];

            SecurityKeyIdentifier ski = new SecurityKeyIdentifier(new SecurityKeyIdentifierClause[] {
                new X509SecurityToken(signingCert).CreateKeyIdentifierClause<X509RawDataKeyIdentifierClause>() });
            X509SigningCredentials signingCreds = new X509SigningCredentials(signingCert, ski);
            descriptor.SigningCredentials = signingCreds;

            Saml2SecurityTokenHandler tokenHandler = new Saml2SecurityTokenHandler();
            Saml2SecurityToken token = tokenHandler.CreateToken(descriptor) as Saml2SecurityToken;

            var sw = new StringWriter();
            tokenHandler.WriteToken(new XmlTextWriter(sw), token);
            //Console.WriteLine(sw.ToString());

            var encodedAssertion = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(sw.ToString()));

            using (var client = new HttpClient())
            {
                try
                {
                    var values = new Dictionary<string, string>
                    {
                        { "grant_type", "urn:ietf:params:oauth:grant-type:saml2-bearer" },
                        { "assertion", encodedAssertion },
                        { "scope", "PRODUCTION" }
                    };
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", "aVIwdTNPOHVSMmxVVHBnRk1KSkVuX2ZSZkJVYTpOR1VsS1FoSER4bkxiNU9JM2xja2F1V0tUZ0Vh");

                    var content = new FormUrlEncodedContent(values);
                    var response = client.PostAsync("https://localhost:9443/oauth2/token", content).Result;
                    var responseString = response.Content.ReadAsStringAsync().Result;
                    Console.WriteLine(responseString);
                } catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    Console.WriteLine(e.StackTrace);
                }               
            }
            Console.ReadLine();
        }
    }
}
