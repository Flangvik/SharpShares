using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;

namespace SharpShares
{
    class Program
    {

        static void Main(string[] args)
        {
     
            List<string> hosts = new List<string>();
            var parsedArgs = Utilities.Options.ParseArgs(args);
            Utilities.Options.Arguments arguments = Utilities.Options.ArgumentValues(parsedArgs);
            Utilities.Options.PrintOptions(arguments);


            System.Net.NetworkCredential cred = null;
            string userSid = "";
            var userMemberOfSids = new List<string>() { };

            //If the arguments contain a domain,username and passwords
            if (!string.IsNullOrEmpty(arguments.userame) && !string.IsNullOrEmpty(arguments.password))
            {
                cred = new System.Net.NetworkCredential(arguments.userame, arguments.password, arguments.userame.Split('\\')[0]);
                var userData = Utilities.LDAP.GetAccountSID(cred, arguments.dc);
                userSid = userData.Item2.AccountDomainSid.Value;
                userMemberOfSids = Utilities.LDAP.GetUserGroupMemberships(cred, arguments.dc, userData.Item1);

            }




            if (!String.IsNullOrEmpty(arguments.ldap))
            {
                List<string> ldap = Utilities.LDAP.SearchLDAP(cred, arguments.dc, arguments.ldap, arguments.verbose);
                hosts = hosts.Concat(ldap).ToList();
            }
            if (!String.IsNullOrEmpty(arguments.ou))
            {
                List<string> ou = Utilities.LDAP.SearchOU(cred, arguments.dc, arguments.ou, arguments.verbose);
                hosts = hosts.Concat(ou).ToList();
            }
            //remove duplicate hosts
            hosts = hosts.Distinct().ToList();
            Utilities.Status.totalCount = hosts.Count;
            Utilities.Status.StartOutputTimer();
            Enums.Shares.GetAllShares(hosts, userSid, userMemberOfSids, arguments);
            Console.ReadLine();
        }
    }
}
