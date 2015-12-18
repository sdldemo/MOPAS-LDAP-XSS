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
            // TODO: AI issue #2, High, Cross-site Scripting, https://github.com/sdldemo/MOPAS-LDAP-XSS/issues/2
            // GET /Tests/1 INPUT DATA VERIFICATION/9 LDAP Injection/Ldap.aspx HTTP/1.1
            // Host:localhost
            // (System.DirectoryServices.DirectorySearcher.FindAll().GetEnumerator().MoveNext() && (System.DirectoryServices.DirectorySearcher.FindAll().GetEnumerator().Current.ToString() == "<script>alert(0)</script>"))
            Response.Write(result);

            // this is our second vulnerability of XSS in this file
            // we will demonstrate what happen if developer fails with his fix (VERIFY Marker)
            // TODO: AI issue #2, High, Cross-site Scripting, https://github.com/sdldemo/MOPAS-LDAP-XSS/issues/2
            // GET /Tests/1 INPUT DATA VERIFICATION/9 LDAP Injection/Ldap.aspx HTTP/1.1
            // Host:localhost
            // (System.DirectoryServices.DirectorySearcher.FindAll().GetEnumerator().MoveNext() && (System.DirectoryServices.DirectorySearcher.FindAll().GetEnumerator().Current.ToString() == "<script>alert(0)</script>"))
            Response.Write(result);

            // this is our third vulnerability of XSS in this file
            // we will demonstrate what happen if we really fix vulnerability (VERIFY Marker)
            // TODO: AI issue #2, High, Cross-site Scripting, https://github.com/sdldemo/MOPAS-LDAP-XSS/issues/2
            // GET /Tests/1 INPUT DATA VERIFICATION/9 LDAP Injection/Ldap.aspx HTTP/1.1
            // Host:localhost
            // (System.DirectoryServices.DirectorySearcher.FindAll().GetEnumerator().MoveNext() && (System.DirectoryServices.DirectorySearcher.FindAll().GetEnumerator().Current.ToString() == "<script>alert(0)</script>"))
            Response.Write(result);

            // this is our fourth vulnerability of XSS in this file
            // we will demonstrate what happen if developer want to cheat (FIXED Marker)
            // TODO: AI issue #2, High, Cross-site Scripting, https://github.com/sdldemo/MOPAS-LDAP-XSS/issues/2
            // GET /Tests/1 INPUT DATA VERIFICATION/9 LDAP Injection/Ldap.aspx HTTP/1.1
            // Host:localhost
            // (System.DirectoryServices.DirectorySearcher.FindAll().GetEnumerator().MoveNext() && (System.DirectoryServices.DirectorySearcher.FindAll().GetEnumerator().Current.ToString() == "<script>alert(0)</script>"))
            Response.Write(result);
        }
    }
}