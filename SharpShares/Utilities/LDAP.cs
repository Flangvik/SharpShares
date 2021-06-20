using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Text;

namespace SharpShares.Utilities
{
    class LDAP
    {

        public static (string, SecurityIdentifier) GetAccountSID(NetworkCredential cred, string dc)
        {
            SecurityIdentifier secId = null;
            string dn = "";
            //https://stackoverflow.com/questions/9477032/how-to-get-username-and-sid-for-user-by-a-domain-name-in-ldap
            DirectoryEntry entry = Networking.GetLdapSearchRoot(cred, "", dc, cred.Domain);
            DirectorySearcher mySearcher = new DirectorySearcher(entry);
            mySearcher.PropertiesToLoad.Add("objectSid");
            mySearcher.PropertiesToLoad.Add("displayName");
            mySearcher.PropertiesToLoad.Add("distinguishedName");

            string cleanUserName = cred.UserName.Split('\\')[1];

            mySearcher.Filter = $"(&(objectclass=user)(|(CN={cleanUserName})(sAMAccountName={cleanUserName})))";
            mySearcher.SizeLimit = int.MaxValue;
            mySearcher.PageSize = int.MaxValue;


            foreach (SearchResult resEnt in mySearcher.FindAll())
            {
                //sometimes objects with empty attributes throw errors
                try
                {
                    secId = new SecurityIdentifier((byte[])resEnt.Properties["objectSid"][0], 0);
                    dn = resEnt.Properties["distinguishedName"][0].ToString();

                }
                catch { /*nothing*/ }
            }
            mySearcher.Dispose();

            return (dn, secId);
        }

        public static List<string> GetUserGroupMemberships(NetworkCredential cred, string dc, string dn)
        {

            var GroupSIDs = new List<string>() { };

            SecurityIdentifier secId = null;
            //https://stackoverflow.com/questions/9477032/how-to-get-username-and-sid-for-user-by-a-domain-name-in-ldap
            DirectoryEntry entry = Networking.GetLdapSearchRoot(cred, "", dc, cred?.Domain);
            DirectorySearcher mySearcher = new DirectorySearcher(entry);
            mySearcher.PropertiesToLoad.Add("objectSid");
            mySearcher.PropertiesToLoad.Add("displayName");



            // mySearcher.Filter = $"(&(member=DN={dn})(objectClass=group))";


            mySearcher.Filter = String.Format("(member:{0}:={1})",
                             "1.2.840.113556.1.4.1941",
                             dn);

            mySearcher.SearchScope = SearchScope.Subtree;

            mySearcher.SizeLimit = int.MaxValue;
            mySearcher.PageSize = int.MaxValue;


            foreach (SearchResult resEnt in mySearcher.FindAll())
            {
                //sometimes objects with empty attributes throw errors
                try
                {
                    secId = new SecurityIdentifier((byte[])resEnt.Properties["objectSid"][0], 0);

                    GroupSIDs.Add(secId.Value);

                }
                catch { /*nothing*/ }
            }
            mySearcher.Dispose();

            return GroupSIDs;



        }

        public static List<string> SearchLDAP(NetworkCredential cred, string dc, string ldap, bool verbose)
        {
            try
            {
                // bool searchGlobalCatalog = true;
                List<string> ComputerNames = new List<string>();
                string description = null;
                string filter = null;

                //https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
                //https://ldapwiki.com/wiki/Active%20Directory%20Computer%20Related%20LDAP%20Query
                switch (ldap)
                {
                    case "all":
                        description = "all enabled computers with \"primary\" group \"Domain Computers\"";
                        filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                        break;
                    case "dc":
                        description = "all enabled Domain Controllers (not read-only DCs)";
                        filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=8192))");
                        break;
                    case "exclude-dc":
                        description = "all enabled computers that are not Domain Controllers or read-only DCs";
                        filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))");
                        break;
                    case "servers":
                        // searchGlobalCatalog = false; //operatingSystem attribute is not replicated in Global Catalog
                        description = "all enabled servers";
                        filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*))");
                        break;
                    case "servers-exclude-dc":
                        //searchGlobalCatalog = false; //operatingSystem attribute is not replicated in Global Catalog
                        description = "all enabled servers excluding Domain Controllers or read-only DCs";
                        filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))");
                        break;
                    default:
                        Console.WriteLine("[!] Invalid LDAP filter: {0}", filter);
                        Utilities.Options.Usage();
                        Environment.Exit(0);
                        break;
                }


                try
                {

                    var entry = Networking.GetLdapSearchRoot(cred, "", dc, cred?.Domain);
                    DirectorySearcher mySearcher = new DirectorySearcher(entry);
                    mySearcher.PropertiesToLoad.Add("dnshostname");
                    mySearcher.PropertiesToLoad.Add("dnshostname");
                    mySearcher.Filter = filter;
                    mySearcher.SizeLimit = int.MaxValue;
                    mySearcher.PageSize = int.MaxValue;
                    Console.WriteLine("[+] Performing LDAP query against the current domain for {0}...", description);
                    Console.WriteLine("[+] This may take some time depending on the size of the environment");

                    foreach (SearchResult resEnt in mySearcher.FindAll())
                    {
                        //sometimes objects with empty attributes throw errors
                        try
                        {
                            string ComputerName = resEnt.Properties["dnshostname"][0].ToString().ToUpper();
                            ComputerNames.Add(ComputerName);
                        }
                        catch { /*nothing*/ }
                    }
                    mySearcher.Dispose();
                }
                catch (Exception ex)
                {
                    if (verbose)
                    {
                        Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                    }
                }

                //localhost returns false positives
                ComputerNames.RemoveAll(u => u.Contains(System.Environment.MachineName.ToUpper()));
                Console.WriteLine("[+] LDAP Search Results: {0}", ComputerNames.Count.ToString());


                return ComputerNames;
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                }
                return null;
            }
        }
        public static List<string> SearchOU(NetworkCredential cred, string dc, string ou, bool verbose)
        {
            try
            {
                List<string> ComputerNames = new List<string>();
                DirectoryEntry entry = Networking.GetLdapSearchRoot(cred, ou, dc, cred?.Domain);

                if (cred != null)
                {

                    entry.Username = cred.UserName;
                    entry.Password = cred.Password;
                }

                DirectorySearcher mySearcher = new DirectorySearcher(entry);
                mySearcher.PropertiesToLoad.Add("dnshostname");
                // filter for all enabled computers
                mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                mySearcher.SizeLimit = int.MaxValue;
                mySearcher.PageSize = int.MaxValue;
                foreach (SearchResult resEnt in mySearcher.FindAll())
                {
                    string ComputerName = resEnt.Properties["dnshostname"][0].ToString();
                    ComputerNames.Add(ComputerName);
                }
                Console.WriteLine("[+] OU Search Results: {0}", ComputerNames.Count().ToString());
                mySearcher.Dispose();
                entry.Dispose();

                return ComputerNames;
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                }
                Environment.Exit(0);
                return null;
            }
        }
    }
}
