using System;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;

namespace Mopas.Tests
{
    /// <summary>
    /// 9.
    /// LADP Injection
    /// MOPAS
    /// Contains 1 vulnerability
    /// </summary>
    public partial class Ldap : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // TODO this todo was here for ages
            var dc = new DirectoryContext(DirectoryContextType.Domain, "ptsecurity.ru");

            var address = Request.Params["address"];
            var filter = "Address=" + address;
            var result = "";

            var domain = Domain.GetDomain(dc);

            // this is our vulnerabilitiy of LDAP injection *in this file*
            // TODO: AI issue #1, High, LDAP Injection, https://github.com/sdldemo/MOPAS-LDAP-XSS/issues/1
            // GET /Tests/1 INPUT DATA VERIFICATION/9 LDAP Injection/Ldap.aspx?address=%7bfilter%7d+%3d+* HTTP/1.1
            // Host:localhost
            var ds = new DirectorySearcher(domain.GetDirectoryEntry(), filter);

            using (var src = ds.FindAll())
            {
                // TODO it was edit here by developer 1 year ago
                foreach (var res in src)
                {
                    result = res.ToString();
                }
            }

            // this is our first vulnerability of XSS in this file
            // we will demonstrate False Positive scenario here (FP Marker)
            Response.Write(result);

            // this is our second vulnerability of XSS in this file
            // we will demonstrate what happen if developer fails with his fix (VERIFY Marker)
            Response.Write(result);

            // this is our third vulnerability of XSS in this file
            // we will demonstrate what happen if we really fix vulnerability (VERIFY Marker)
            Response.Write(result);

            // this is our fourth vulnerability of XSS in this file
            // we will demonstrate what happen if developer want to cheat (FIXED Marker)
            Response.Write(result);
        }
    }
}