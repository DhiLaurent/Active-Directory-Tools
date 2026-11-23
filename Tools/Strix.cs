using System;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Threading;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.DirectoryServices.ActiveDirectory;

namespace Strix
{
    class Program
    {
        private static readonly Random Rnd = new Random();

        static void Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;

            if (args.Length == 0)
            {
                PrintBanner();
                return;
            }

            string action = args[0].ToLower();

            switch (action)
            {
                case "domaininfo":
                    GetDomainInfo();
                    break;
                case "dcs":
                    GetDomainControllers();
                    break;
                case "users":
                    EnumDomainUsers();
                    break;
                case "computers":
                    EnumDomainComputers();
                    break;
                case "groups":
                    EnumDomainGroups();
                    break;
                case "groupmembers":
                    if (args.Length > 1)
                        EnumGroupMembers(args[1]);
                    else
                        PrintColored("[-] Informe o grupo. Ex: Strix.exe groupmembers \"Domain Admins\"", ConsoleColor.Red);
                    break;
                case "trust":
                    GetDomainTrusts();
                    break;
                case "acls":
                    FindInterestingACLs();
                    break;
                case "foreign":
                    FindForeignPrincipals();
                    break;
                case "kerberoast":
                    FindKerberoastable();
                    break;
                case "asrep":
                    FindASREPRoastable();
                    break;
                case "delegations":
                    FindDelegations();
                    break;
                case "gpos":
                    FindGPOs();
                    break;
                case "writeablegpos":
                    FindWriteableGPOs();
                    break;
                case "gpolinks":
                    FindGPOLinks();
                    break;
                case "gplinkpermissions":
                    FindGPLinkPermissions();
                    break;
                case "gpocreators":
                    FindGPOCreators();
                    break;
                case "gpocreate":
                    CreateGPO(args);
                    break;
                case "gpocreatelink":
                    CreateGPOLink(args);
                    break;
                case "gposcheduletask":
                    CreateGPOScheduledTask(args);
                    break;



                default:
                    PrintColored(String.Format("[-] Acao desconhecida: {0}", action), ConsoleColor.Red);
                    PrintBanner();
                    break;
            }
        }

        static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("==================================================");
            Console.WriteLine("        Strix -  ADSI based Tool                  ");
            Console.WriteLine("==================================================");
            Console.ResetColor();
            Console.WriteLine("Modos de uso disponiveis:");
            Console.WriteLine("  Core:");
            Console.WriteLine("    Strix.exe domaininfo");
            Console.WriteLine("    Strix.exe dcs");
            Console.WriteLine("    Strix.exe users");
            Console.WriteLine("    Strix.exe computers");
            Console.WriteLine("    Strix.exe groups");
            Console.WriteLine("    Strix.exe groupmembers \"Grupo\"");
            Console.WriteLine("    Strix.exe trust");
            Console.WriteLine("  ACLs & Relacionamentos:");
            Console.WriteLine("    Strix.exe acls        (DACLs perigosas explicitas)");
            Console.WriteLine("    Strix.exe foreign     (Foreign Principals em grupos)");
            Console.WriteLine("  Kerberos & Delegacoes:");
            Console.WriteLine("    Strix.exe kerberoast  (Contas alvo de Kerberoasting)");
            Console.WriteLine("    Strix.exe asrep       (Contas com AS-REP Roasting)");
            Console.WriteLine("    Strix.exe delegations (Unconstrained, Constrained, RBCD)");
            Console.WriteLine("  GPOs (Group Policies):");
            Console.WriteLine("    Strix.exe gpos          (Listar todas as GPOs)");
            Console.WriteLine("    Strix.exe writeablegpos (GPOs com permissoes nao-padrao)");
            Console.WriteLine("    Strix.exe gpolinks          (Onde as GPOs estao vinculadas)");
            Console.WriteLine("    Strix.exe gplinkpermissions (Quem pode vincular GPOs)");
            Console.WriteLine("    Strix.exe gpocreators       (Quem pode criar GPOs)");
            Console.WriteLine("    Strix.exe gpocreate <NomeDaGPO> [Dominio.local]");
            Console.WriteLine("    Strix.exe gpocreatelink <GPO> <Dominio.local> <domain|ou|site> [NomeOuDN]");
            Console.WriteLine("    Strix.exe gposcheduletask <GPO> <cmd|powershell> <machine|user> \"<comando>\"");

        }

        private static void PrintColored(string text, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ResetColor();
        }

        public static void GetDomainInfo()
        {
            PrintColored("[*] Coletando informacoes basicas do dominio via RootDSE...", ConsoleColor.Yellow);
            try
            {
                using (DirectoryEntry rootDse = new DirectoryEntry("LDAP://RootDSE"))
                {
                    string defaultNamingContext = rootDse.Properties["defaultNamingContext"].Value != null ? rootDse.Properties["defaultNamingContext"].Value.ToString() : "";
                    string dnsHostName = rootDse.Properties["dnsHostName"].Value != null ? rootDse.Properties["dnsHostName"].Value.ToString() : "";

                    Console.WriteLine(String.Format("    [+] Contexto Padrao : {0}", defaultNamingContext));
                    Console.WriteLine(String.Format("    [+] DC Principal    : {0}", dnsHostName));

                    if (!string.IsNullOrEmpty(defaultNamingContext))
                    {
                        using (DirectoryEntry domainEntry = new DirectoryEntry(String.Format("LDAP://{0}", defaultNamingContext)))
                        {
                            byte[] sidBytes = (byte[])domainEntry.Properties["objectSid"].Value;
                            SecurityIdentifier sid = new SecurityIdentifier(sidBytes, 0);
                            Console.WriteLine(String.Format("    [+] Domain SID      : {0}", sid));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                PrintColored(String.Format("[-] Erro ao coletar info do dominio: {0}", ex.Message), ConsoleColor.Red);
            }
        }

        public static void GetDomainControllers()
        {
            PrintColored("[*] Enumerando Domain Controllers...", ConsoleColor.Yellow);
            try
            {
                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";
                    searcher.PropertiesToLoad.Add("cn");
                    searcher.PropertiesToLoad.Add("dNSHostName");

                    int count = 0;
                    foreach (SearchResult result in searcher.FindAll())
                    {
                        string cn = result.Properties["cn"].Count > 0 ? result.Properties["cn"][0].ToString() : "N/A";
                        string dns = result.Properties["dNSHostName"].Count > 0 ? result.Properties["dNSHostName"][0].ToString() : "N/A";
                        Console.WriteLine(String.Format("    [+] DC Encontrado: {0} ({1})", cn, dns));
                        count++;
                    }
                    PrintColored(String.Format("[*] Total de DCs encontrados: {0}", count), ConsoleColor.DarkGray);
                }
            }
            catch (Exception ex)
            {
                PrintColored(String.Format("[-] Erro ao enumerar DCs: {0}", ex.Message), ConsoleColor.Red);
            }
        }

        public static void EnumDomainUsers()
        {
            PrintColored("[*] Executando enumeracao cirurgica de usuarios...", ConsoleColor.Yellow);
            try
            {
                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    searcher.Filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    searcher.PropertiesToLoad.Add("description");

                    int count = 0;
                    foreach (SearchResult result in searcher.FindAll())
                    {
                        string sam = result.Properties["sAMAccountName"][0].ToString();
                        string desc = result.Properties["description"].Count > 0 ? result.Properties["description"][0].ToString() : "";

                        if (!string.IsNullOrEmpty(desc))
                            Console.WriteLine(String.Format("    [+] {0,-20} | Desc: {1}", sam, desc));
                        else
                            Console.WriteLine(String.Format("    [+] {0}", sam));

                        count++;
                    }
                    PrintColored(String.Format("[*] Total de usuarios ativos: {0}", count), ConsoleColor.DarkGray);
                }
            }
            catch (Exception ex)
            {
                PrintColored(String.Format("[-] Erro: {0}", ex.Message), ConsoleColor.Red);
            }
        }

        public static void EnumDomainComputers()
        {
            PrintColored("[*] Enumerando computadores do dominio...", ConsoleColor.Yellow);
            try
            {
                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    searcher.Filter = "(objectCategory=computer)";
                    searcher.PropertiesToLoad.Add("name");
                    searcher.PropertiesToLoad.Add("operatingSystem");

                    int count = 0;
                    foreach (SearchResult result in searcher.FindAll())
                    {
                        string name = result.Properties["name"][0].ToString();
                        string os = result.Properties["operatingSystem"].Count > 0 ? result.Properties["operatingSystem"][0].ToString() : "N/A";

                        Console.WriteLine(String.Format("    [+] Host: {0,-20} | OS: {1}", name, os));
                        count++;
                    }
                    PrintColored(String.Format("[*] Total de computadores: {0}", count), ConsoleColor.DarkGray);
                }
            }
            catch (Exception ex)
            {
                PrintColored(String.Format("[-] Erro: {0}", ex.Message), ConsoleColor.Red);
            }
        }

        public static void EnumDomainGroups()
        {
            PrintColored("[*] Enumerando grupos do dominio...", ConsoleColor.Yellow);
            try
            {
                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    searcher.Filter = "(objectCategory=group)";
                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    searcher.PropertiesToLoad.Add("description");

                    int count = 0;
                    foreach (SearchResult result in searcher.FindAll())
                    {
                        string groupName = result.Properties["sAMAccountName"].Count > 0 ? result.Properties["sAMAccountName"][0].ToString() : "N/A";
                        string desc = result.Properties["description"].Count > 0 ? result.Properties["description"][0].ToString() : "";

                        if (!string.IsNullOrEmpty(desc))
                            Console.WriteLine(String.Format("    [+] {0,-25} | Desc: {1}", groupName, desc));
                        else
                            Console.WriteLine(String.Format("    [+] {0}", groupName));

                        count++;
                    }
                    PrintColored(String.Format("[*] Total de grupos: {0}", count), ConsoleColor.DarkGray);
                }
            }
            catch (Exception ex)
            {
                PrintColored(String.Format("[-] Erro ao enumerar grupos: {0}", ex.Message), ConsoleColor.Red);
            }
        }

        public static void EnumGroupMembers(string targetGroup)
        {
            PrintColored(String.Format("[*] Buscando membros do grupo: {0}", targetGroup), ConsoleColor.Yellow);
            try
            {
                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    searcher.Filter = String.Format("(&(objectCategory=group)(sAMAccountName={0}))", targetGroup);
                    searcher.PropertiesToLoad.Add("distinguishedName");

                    SearchResult result = searcher.FindOne();
                    if (result == null)
                    {
                        PrintColored("    [-] Grupo nao encontrado.", ConsoleColor.Red);
                        return;
                    }

                    DirectoryEntry groupEntry = result.GetDirectoryEntry();
                    if (groupEntry.Properties["member"].Count == 0)
                    {
                        PrintColored("    [+] O grupo esta vazio.", ConsoleColor.Cyan);
                        return;
                    }

                    int count = 0;
                    foreach (var memberDn in groupEntry.Properties["member"])
                    {
                        string memberName = ResolveDnToSamAccountName(memberDn.ToString());
                        Console.WriteLine(String.Format("    ├── {0} ({1})", memberName, memberDn.ToString()));
                        count++;
                    }
                    PrintColored(String.Format("[*] Total de membros no grupo '{0}': {1}", targetGroup, count), ConsoleColor.DarkGray);
                }
            }
            catch (Exception ex)
            {
                PrintColored(String.Format("[-] Erro ao buscar membros: {0}", ex.Message), ConsoleColor.Red);
            }
        }

        private static string ResolveDnToSamAccountName(string distinguishedName)
        {
            try
            {
                using (DirectoryEntry memberEntry = new DirectoryEntry(String.Format("LDAP://{0}", distinguishedName)))
                {
                    if (memberEntry.Properties["sAMAccountName"].Value != null)
                    {
                        return memberEntry.Properties["sAMAccountName"].Value.ToString();
                    }
                }
            }
            catch { }
            return distinguishedName;
        }

        public static void GetDomainTrusts()
        {
            PrintColored("[*] Mapeando relacoes de confianca (Domain Trusts)...", ConsoleColor.Yellow);
            try
            {
                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    searcher.Filter = "(objectClass=trustedDomain)";
                    searcher.PropertiesToLoad.Add("name");

                    SearchResultCollection results = searcher.FindAll();
                    if (results.Count == 0)
                    {
                        PrintColored("    [+] Nenhuma relacao de confianca externa encontrada.", ConsoleColor.Cyan);
                    }
                    else
                    {
                        foreach (SearchResult result in results)
                        {
                            string trustName = result.Properties["name"].Count > 0 ? result.Properties["name"][0].ToString() : "N/A";
                            Console.WriteLine(String.Format("    [+] Trust Detectado: {0}", trustName));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                PrintColored(String.Format("[-] Erro ao mapear trusts: {0}", ex.Message), ConsoleColor.Red);
            }
        }

        public static void FindInterestingACLs()
        {
            PrintColored("[*] Analisando DACLs explicitas em busca de caminhos reais de escalonamento...", ConsoleColor.Yellow);
            try
            {
                string currentDomainSid = GetCurrentDomainSid();

                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    searcher.Filter = "(|(objectCategory=person)(objectCategory=computer)(objectCategory=group))";
                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    searcher.PropertiesToLoad.Add("objectSid");
                    searcher.PageSize = 250;

                    int findings = 0;
                    foreach (SearchResult result in searcher.FindAll())
                    {
                        try
                        {
                            string targetName = result.Properties["sAMAccountName"].Count > 0 ? result.Properties["sAMAccountName"][0].ToString() : "N/A";
                            string targetSid = "";
                            if (result.Properties["objectSid"].Count > 0)
                            {
                                byte[] targetSidBytes = (byte[])result.Properties["objectSid"][0];
                                targetSid = new SecurityIdentifier(targetSidBytes, 0).Value;
                            }

                            DirectoryEntry entry = result.GetDirectoryEntry();
                            AuthorizationRuleCollection rules = entry.ObjectSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));

                            foreach (AuthorizationRule rule in rules)
                            {
                                ActiveDirectoryAccessRule adRule = rule as ActiveDirectoryAccessRule;
                                if (adRule != null)
                                {
                                    if (adRule.IsInherited) continue;
                                    if (adRule.AccessControlType != AccessControlType.Allow) continue;

                                    string accessorSid = adRule.IdentityReference.Value;
                                    if (accessorSid == targetSid || accessorSid == "S-1-5-10") continue;

                                    if (accessorSid == "S-1-5-18" ||
                                        accessorSid == "S-1-5-32-544" ||
                                        accessorSid.EndsWith("-512") ||
                                        accessorSid.EndsWith("-519") ||
                                        accessorSid.EndsWith("-518") ||
                                        accessorSid.EndsWith("-544") ||
                                        accessorSid.EndsWith("-548"))
                                    {
                                        continue;
                                    }

                                    string rights = adRule.ActiveDirectoryRights.ToString();
                                    bool isDangerous = rights.Contains("GenericAll") ||
                                                       rights.Contains("GenericWrite") ||
                                                       rights.Contains("WriteDacl") ||
                                                       rights.Contains("WriteOwner") ||
                                                       rights.Contains("Self") && rights.Contains("WriteProperty");

                                    if (isDangerous)
                                    {
                                        string accessorName = ResolveSidToName(accessorSid);
                                        string msg = String.Format("    [!] ACL Perigosa Explicita! Alvo: {0} <-- Permissao: [{1}] concedida para: {2} ({3})",
                                            targetName, rights, accessorName, accessorSid);

                                        Console.WriteLine(msg);
                                        findings++;
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                    PrintColored(String.Format("[*] Varredura finalizada. ACLs explicitas e nao-privilegiadas: {0} encontradas.", findings), ConsoleColor.DarkGray);
                }
            }
            catch (Exception ex)
            {
                PrintColored(String.Format("[-] Erro ao varrer ACLs: {0}", ex.Message), ConsoleColor.Red);
            }
        }

        public static void FindForeignPrincipals()
        {
            PrintColored("[*] Enumerando Foreign Principals...", ConsoleColor.Yellow);
            try
            {
                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    searcher.Filter = "(objectCategory=group)";
                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    searcher.PropertiesToLoad.Add("member");

                    string currentDomainSid = GetCurrentDomainSid();
                    int foreignCount = 0;

                    foreach (SearchResult result in searcher.FindAll())
                    {
                        string groupName = result.Properties["sAMAccountName"][0].ToString();
                        DirectoryEntry groupEntry = result.GetDirectoryEntry();

                        foreach (var memberDn in groupEntry.Properties["member"])
                        {
                            string memberDnStr = memberDn.ToString();
                            string memberSid = ResolveDnToSid(memberDnStr);

                            if (!string.IsNullOrEmpty(memberSid) && !string.IsNullOrEmpty(currentDomainSid))
                            {
                                if (!memberSid.StartsWith(currentDomainSid))
                                {
                                    string msg = String.Format("    [!] Foreign Principal detectado no grupo '{0}': {1} (SID: {2})",
                                        groupName, memberDnStr, memberSid);

                                    Console.WriteLine(msg);
                                    foreignCount++;
                                }
                            }
                        }
                    }
                    PrintColored(String.Format("[*] Varredura concluida. Total de Foreign Principals: {0}", foreignCount), ConsoleColor.DarkGray);
                }
            }
            catch (Exception ex)
            {
                PrintColored(String.Format("[-] Erro ao buscar Foreign Principals: {0}", ex.Message), ConsoleColor.Red);
            }
        }

        public static void FindKerberoastable()
        {
            PrintColored("[*] Buscando contas alvo de Kerberoasting (SPN configurado)...", ConsoleColor.Yellow);
            try
            {
                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    searcher.Filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
                    searcher.PropertiesToLoad.Add("sAMAccountName");
                    searcher.PropertiesToLoad.Add("servicePrincipalName");

                    int count = 0;
                    foreach (SearchResult result in searcher.FindAll())
                    {
                        string sam = result.Properties["sAMAccountName"][0].ToString();
                        string spns = "";
                        foreach (var spn in result.Properties["servicePrincipalName"])
                        {
                            spns += spn.ToString() + " ";
                        }

                        Console.WriteLine(String.Format("    [!] Kerberoastable User: {0}", sam));
                        Console.WriteLine(String.Format("        └── SPNs: {0}", spns.Trim()));
                        count++;
                    }
                    PrintColored(String.Format("[*] Total de contas Kerberoastable encontradas: {0}", count), ConsoleColor.DarkGray);
                }
            }
            catch (Exception ex)
            {
                PrintColored(String.Format("[-] Erro ao buscar alvos Kerberoast: {0}", ex.Message), ConsoleColor.Red);
            }
        }

        public static void FindASREPRoastable()
        {
            PrintColored("[*] Buscando contas com AS-REP Roasting (Pre-autenticacao Kerberos desativada)...", ConsoleColor.Yellow);
            try
            {
                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    searcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
                    searcher.PropertiesToLoad.Add("sAMAccountName");

                    int count = 0;
                    foreach (SearchResult result in searcher.FindAll())
                    {
                        string sam = result.Properties["sAMAccountName"][0].ToString();
                        Console.WriteLine(String.Format("    [!] AS-REP Roastable User: {0}", sam));
                        count++;
                    }
                    PrintColored(String.Format("[*] Total de contas AS-REP Roastable encontradas: {0}", count), ConsoleColor.DarkGray);
                }
            }
            catch (Exception ex)
            {
                PrintColored(String.Format("[-] Erro ao buscar alvos AS-REP: {0}", ex.Message), ConsoleColor.Red);
            }
        }

        public static void FindDelegations()
        {
            PrintColored("[*] Mapeando configuracoes de Delegacao com profundidade cirurgica...", ConsoleColor.Yellow);
            try
            {
                // 1. Unconstrained Delegation
                PrintColored("\n[*] [1/3] Verificando Unconstrained Delegation...", ConsoleColor.Cyan);
                using (DirectorySearcher searcherUnc = new DirectorySearcher())
                {
                    searcherUnc.Filter = "(&(|(objectCategory=computer)(objectCategory=person))(userAccountControl:1.2.840.113556.1.4.803:=524288))";
                    searcherUnc.PropertiesToLoad.Add("sAMAccountName");
                    searcherUnc.PropertiesToLoad.Add("operatingSystem");

                    int uncCount = 0;
                    foreach (SearchResult res in searcherUnc.FindAll())
                    {
                        string name = res.Properties["sAMAccountName"].Count > 0 ? res.Properties["sAMAccountName"][0].ToString() : "N/A";
                        string os = res.Properties["operatingSystem"].Count > 0 ? res.Properties["operatingSystem"][0].ToString() : "N/A";

                        Console.WriteLine(String.Format("    [!] Unconstrained Host/User: {0,-20} | OS: {1}", name, os));
                        uncCount++;
                    }
                    if (uncCount == 0) PrintColored("    [+] Nenhuma delegacao irrestrita encontrada.", ConsoleColor.DarkGray);
                }

                // 2. Constrained Delegation
                PrintColored("\n[*] [2/3] Verificando Constrained Delegation e Protocol Transition...", ConsoleColor.Cyan);
                using (DirectorySearcher searcherCon = new DirectorySearcher())
                {
                    searcherCon.Filter = "(&(|(objectCategory=computer)(objectCategory=person))(msDS-AllowedToDelegateTo=*))";
                    searcherCon.PropertiesToLoad.Add("sAMAccountName");
                    searcherCon.PropertiesToLoad.Add("msDS-AllowedToDelegateTo");
                    searcherCon.PropertiesToLoad.Add("userAccountControl");

                    int conCount = 0;
                    foreach (SearchResult res in searcherCon.FindAll())
                    {
                        string name = res.Properties["sAMAccountName"].Count > 0 ? res.Properties["sAMAccountName"][0].ToString() : "N/A";
                        int uac = res.Properties["userAccountControl"].Count > 0 ? Convert.ToInt32(res.Properties["userAccountControl"][0]) : 0;

                        bool protocolTransition = (uac & 16777216) != 0;
                        string delegationType = protocolTransition ? "Constrained w/ Protocol Transition" : "Constrained (Kerberos Only)";

                        Console.WriteLine(String.Format("    [!] Alvo: {0} | Tipo: [{1}]", name, delegationType));

                        if (res.Properties["msDS-AllowedToDelegateTo"].Count > 0)
                        {
                            foreach (var targetSpn in res.Properties["msDS-AllowedToDelegateTo"])
                            {
                                Console.WriteLine(String.Format("        └── Delega para SPN: {0}", targetSpn.ToString()));
                            }
                        }
                        conCount++;
                    }
                    if (conCount == 0) PrintColored("    [+] Nenhuma delegacao restrita encontrada.", ConsoleColor.DarkGray);
                }

                // 3. Resource-Based Constrained Delegation (RBCD)
                PrintColored("\n[*] [3/3] Verificando Resource-Based Constrained Delegation (RBCD) e suas ACLs...", ConsoleColor.Cyan);
                using (DirectorySearcher searcherRbcd = new DirectorySearcher())
                {
                    searcherRbcd.Filter = "(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))";
                    searcherRbcd.PropertiesToLoad.Add("sAMAccountName");
                    searcherRbcd.PropertiesToLoad.Add("msDS-AllowedToActOnBehalfOfOtherIdentity");

                    int rbcdCount = 0;
                    foreach (SearchResult res in searcherRbcd.FindAll())
                    {
                        string targetName = res.Properties["sAMAccountName"].Count > 0 ? res.Properties["sAMAccountName"][0].ToString() : "N/A";
                        Console.WriteLine(String.Format("    [!] Recurso com RBCD Alvo: {0}", targetName));

                        try
                        {
                            if (res.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Count > 0)
                            {
                                byte[] secDescriptorBytes = (byte[])res.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"][0];
                                RawSecurityDescriptor rawSd = new RawSecurityDescriptor(secDescriptorBytes, 0);

                                if (rawSd.DiscretionaryAcl != null)
                                {
                                    foreach (CommonAce commonAce in rawSd.DiscretionaryAcl)
                                    {
                                        SecurityIdentifier accessorSid = commonAce.SecurityIdentifier;
                                        string accessorName = ResolveSidToName(accessorSid.Value);

                                        Console.WriteLine(String.Format("        └── Concedido para: {0} ({1})",
                                            accessorName, accessorSid.Value));
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("        [-] O atributo de delegacao esta vazio.");
                            }
                        }
                        catch (Exception exInner)
                        {
                            Console.WriteLine(String.Format("        [-] Erro ao parsear ACL do RBCD: {0}", exInner.Message));
                        }

                        rbcdCount++;
                    }
                    if (rbcdCount == 0) PrintColored("    [+] Nenhuma configuracao de RBCD encontrada.", ConsoleColor.DarkGray);
                }

                PrintColored("\n[*] Mapeamento avancado de delegacoes concluido.", ConsoleColor.DarkGray);
            }
            catch (Exception ex)
            {
                PrintColored(String.Format("[-] Erro ao mapear delegacoes: {0}", ex.Message), ConsoleColor.Red);
            }
        }

        public static void FindGPOs()
        {
            PrintColored("[*] Enumerando todas as GPOs (Group Policy Objects) do dominio...", ConsoleColor.Yellow);
            try
            {
                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    searcher.Filter = "(objectClass=groupPolicyContainer)";
                    searcher.PropertiesToLoad.Add("displayName");
                    searcher.PropertiesToLoad.Add("name");
                    searcher.PropertiesToLoad.Add("gPCFileSysPath");

                    int count = 0;
                    foreach (SearchResult result in searcher.FindAll())
                    {
                        string displayName = result.Properties["displayName"].Count > 0 ? result.Properties["displayName"][0].ToString() : "N/A";
                        string name = result.Properties["name"].Count > 0 ? result.Properties["name"][0].ToString() : "N/A";
                        string syspath = result.Properties["gPCFileSysPath"].Count > 0 ? result.Properties["gPCFileSysPath"][0].ToString() : "N/A";

                        Console.WriteLine(String.Format("    [+] GPO: {0,-30} | GUID: {1}", displayName, name));
                        Console.WriteLine(String.Format("        └── Caminho SYSVOL: {0}", syspath));
                        count++;
                    }
                    PrintColored(String.Format("[*] Total de GPOs encontradas: {0}", count), ConsoleColor.DarkGray);
                }
            }
            catch (Exception ex)
            {
                PrintColored(String.Format("[-] Erro ao enumerar GPOs: {0}", ex.Message), ConsoleColor.Red);
            }
        }

        public static void FindWriteableGPOs()
        {
            PrintColored("[*] Analisando DACLs em GPOs em busca de permissões reais de escrita (ignorando CREATOR OWNER e Builtins)...", ConsoleColor.Yellow);
            try
            {
                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    searcher.Filter = "(objectClass=groupPolicyContainer)";
                    searcher.PropertiesToLoad.Add("displayName");
                    searcher.PropertiesToLoad.Add("name");
                    searcher.PageSize = 250;

                    int findings = 0;
                    foreach (SearchResult result in searcher.FindAll())
                    {
                        try
                        {
                            string displayName = result.Properties["displayName"].Count > 0 ? result.Properties["displayName"][0].ToString() : "N/A";
                            string gpoGuid = result.Properties["name"].Count > 0 ? result.Properties["name"][0].ToString() : "N/A";

                            DirectoryEntry entry = result.GetDirectoryEntry();
                            AuthorizationRuleCollection rules = entry.ObjectSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));

                            foreach (AuthorizationRule rule in rules)
                            {
                                ActiveDirectoryAccessRule adRule = rule as ActiveDirectoryAccessRule;
                                if (adRule != null)
                                {
                                    if (adRule.IsInherited) continue;
                                    if (adRule.AccessControlType != AccessControlType.Allow) continue;

                                    string accessorSid = adRule.IdentityReference.Value;

                                    // Ignora contas padrão, Built-ins de alto privilégio e CREATOR OWNER (S-1-3-0)
                                    if (accessorSid == "S-1-3-0" ||
                                        accessorSid == "S-1-5-18" ||
                                        accessorSid == "S-1-5-32-544" ||
                                        accessorSid == "S-1-5-10" ||
                                        accessorSid.EndsWith("-512") ||
                                        accessorSid.EndsWith("-519") ||
                                        accessorSid.EndsWith("-518") ||
                                        accessorSid.EndsWith("-544"))
                                    {
                                        continue;
                                    }

                                    string rights = adRule.ActiveDirectoryRights.ToString();

                                    bool isWriteable = rights.Contains("GenericAll") ||
                                                       rights.Contains("WriteDacl") ||
                                                       rights.Contains("WriteOwner");

                                    if (isWriteable)
                                    {
                                        string accessorName = ResolveSidToName(accessorSid);
                                        Console.WriteLine(String.Format("    [!] GPO Vulneravel! Nome: {0} ({1})", displayName, gpoGuid));
                                        Console.WriteLine(String.Format("        └── Permissao: [{0}] concedida para: {1} ({2})", rights, accessorName, accessorSid));
                                        findings++;
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                    PrintColored(String.Format("[*] Varredura de GPOs concluida. Total de GPOs vulneraveis reais: {0}", findings), ConsoleColor.DarkGray);
                }
            }
            catch (Exception ex)
            {
                PrintColored(String.Format("[-] Erro ao varrer GPOs writeable: {0}", ex.Message), ConsoleColor.Red);
            }
        }

        private static string ResolveSidToName(string sidString)
        {
            try
            {
                SecurityIdentifier sid = new SecurityIdentifier(sidString);
                NTAccount account = (NTAccount)sid.Translate(typeof(NTAccount));
                return account.ToString();
            }
            catch
            {
                return sidString;
            }
        }

        private static string GetCurrentDomainSid()
        {
            try
            {
                using (DirectoryEntry rootDse = new DirectoryEntry("LDAP://RootDSE"))
                {
                    string defaultNamingContext = rootDse.Properties["defaultNamingContext"].Value.ToString();
                    using (DirectoryEntry domainEntry = new DirectoryEntry(String.Format("LDAP://{0}", defaultNamingContext)))
                    {
                        byte[] sidBytes = (byte[])domainEntry.Properties["objectSid"].Value;
                        SecurityIdentifier sid = new SecurityIdentifier(sidBytes, 0);
                        return sid.Value;
                    }
                }
            }
            catch
            {
                return "";
            }
        }

        private static string ResolveDnToSid(string distinguishedName)
        {
            try
            {
                using (DirectoryEntry entry = new DirectoryEntry(String.Format("LDAP://{0}", distinguishedName)))
                {
                    if (entry.Properties["objectSid"].Value != null)
                    {
                        byte[] sidBytes = (byte[])entry.Properties["objectSid"].Value;
                        SecurityIdentifier sid = new SecurityIdentifier(sidBytes, 0);
                        return sid.Value;
                    }
                }
            }
            catch { }
            return "";
        }

        public static void FindGPOLinks()
        {
            PrintColored("[*] Enumerando vinculos de GPO em Domain, Sites e OUs...", ConsoleColor.Yellow);

            try
            {
                string defaultNC;
                string configurationNC;
                GetGpoNamingContexts(out defaultNC, out configurationNC);

                Dictionary<string, string> gpoNames = GetGpoNameMap(defaultNC);
                int totalLinks = 0;

                EnumerateGpoScopes(defaultNC, configurationNC, delegate(SearchResult result, string scope)
                {
                    string gPLink = GetGpoProperty(result, "gPLink");
                    if (String.IsNullOrEmpty(gPLink))
                        return;

                    string dn = GetGpoProperty(result, "distinguishedName");
                    string scopeName = GetGpoProperty(result, "name");
                    if (String.IsNullOrEmpty(scopeName))
                        scopeName = dn;

                    int gPOptions = GetGpoIntProperty(result, "gPOptions");
                    bool blockInheritance = (gPOptions & 1) != 0;

                    MatchCollection matches = Regex.Matches(
                        gPLink,
                        @"\[LDAP://(.*?);(\d+)\]",
                        RegexOptions.IgnoreCase
                    );

                    if (matches.Count == 0)
                        return;

                    Console.WriteLine("\n[+] Escopo: " + scope);
                    Console.WriteLine("    Nome: " + scopeName);
                    Console.WriteLine("    DN: " + dn);

                    if (scope != "Site")
                        Console.WriteLine("    Block Inheritance: " + (blockInheritance ? "Yes" : "No"));

                    int linkOrder = 0;

                    foreach (Match match in matches)
                    {
                        linkOrder++;

                        string gpoDN = match.Groups[1].Value;
                        int options = Convert.ToInt32(match.Groups[2].Value);

                        bool disabled = (options & 1) != 0;
                        bool enforced = (options & 2) != 0;

                        string guid = ExtractGpoGuid(gpoDN);
                        string displayName = "Unknown GPO";

                        if (!String.IsNullOrEmpty(guid) && gpoNames.ContainsKey(guid))
                            displayName = gpoNames[guid];

                        Console.WriteLine("\n    GPO: " + displayName);
                        Console.WriteLine("    GUID: " + (guid ?? "Unknown"));
                        Console.WriteLine("    Link Order: " + linkOrder);
                        Console.WriteLine("    Link Status: " + (disabled ? "Disabled" : "Enabled"));
                        Console.WriteLine("    Enforced: " + (enforced ? "Yes" : "No"));
                        Console.WriteLine("    GPO DN: " + gpoDN);

                        totalLinks++;
                    }
                });

                PrintColored("[*] Total de vinculos encontrados: " + totalLinks, ConsoleColor.DarkGray);
                Console.WriteLine("[*] Nota: os vinculos sao feitos em Domain, Sites e OUs; nao diretamente em usuarios ou computadores.");
            }
            catch (Exception ex)
            {
                PrintColored("[-] Erro ao enumerar GPO Links: " + ex.Message, ConsoleColor.Red);
            }
        }

        private static bool HasAllRights(ActiveDirectoryRights actual, ActiveDirectoryRights requested)
        {
            return (actual & requested) == requested;
        }

        private static bool IsKnownAdministrativeSid(string sid)
        {
            if (String.IsNullOrEmpty(sid))
                return false;

            if (sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20" ||
                sid == "S-1-5-32-544" || sid == "S-1-5-32-548" ||
                sid == "S-1-5-32-549" || sid == "S-1-5-32-550" ||
                sid == "S-1-5-32-551")
                return true;

            string domainSid = GetCurrentDomainSid();
            if (!String.IsNullOrEmpty(domainSid) &&
                sid.StartsWith(domainSid + "-", StringComparison.OrdinalIgnoreCase))
            {
                string rid = sid.Substring(domainSid.Length + 1);
                return rid == "512" || rid == "516" || rid == "518" || rid == "519";
            }

            return false;
        }

        private static string EscapeSidForLdap(string sid)
        {
            SecurityIdentifier identifier = new SecurityIdentifier(sid);
            byte[] bytes = new byte[identifier.BinaryLength];
            identifier.GetBinaryForm(bytes, 0);

            System.Text.StringBuilder escaped = new System.Text.StringBuilder();
            foreach (byte value in bytes)
                escaped.Append("\\").Append(value.ToString("X2"));

            return escaped.ToString();
        }

        private static bool IsPrivilegedPrincipal(string sid)
        {
            if (IsKnownAdministrativeSid(sid))
                return true;

            try
            {
                using (DirectorySearcher searcher = new DirectorySearcher())
                {
                    searcher.Filter = "(objectSid=" + EscapeSidForLdap(sid) + ")";
                    searcher.SearchScope = SearchScope.Subtree;
                    searcher.PropertiesToLoad.Add("tokenGroups");

                    SearchResult result = searcher.FindOne();
                    if (result == null || result.Properties["tokenGroups"].Count == 0)
                        return false;

                    foreach (byte[] groupSidBytes in result.Properties["tokenGroups"])
                    {
                        string groupSid = new SecurityIdentifier(groupSidBytes, 0).Value;
                        if (IsKnownAdministrativeSid(groupSid))
                            return true;
                    }
                }
            }
            catch
            {

            }

            return false;
        }

        public static void FindGPLinkPermissions()
        {
            PrintColored("[*] Enumerando permissoes para vincular GPOs...", ConsoleColor.Yellow);

            try
            {
                string defaultNC;
                string configurationNC;
                GetGpoNamingContexts(out defaultNC, out configurationNC);

                int allowFindings = 0;
                int denyFindings = 0;

                EnumerateGpoScopes(defaultNC, configurationNC, delegate(SearchResult result, string scope)
                {
                    string dn = GetGpoProperty(result, "distinguishedName");
                    string name = GetGpoProperty(result, "name");

                    using (DirectoryEntry entry = result.GetDirectoryEntry())
                    {
                        try
                        {
                            AuthorizationRuleCollection rules = entry.ObjectSecurity.GetAccessRules(
                                true, true, typeof(SecurityIdentifier));

                            foreach (AuthorizationRule rule in rules)
                            {
                                ActiveDirectoryAccessRule ace = rule as ActiveDirectoryAccessRule;
                                if (ace == null)
                                    continue;

                                string sid = ace.IdentityReference.Value;

                                if (sid == "S-1-3-0" || sid == "S-1-5-10" || IsPrivilegedPrincipal(sid))
                                    continue;

                                ActiveDirectoryRights rights = ace.ActiveDirectoryRights;

                                bool genericAll = HasAllRights(rights, ActiveDirectoryRights.GenericAll);
                                bool genericWrite = HasAllRights(rights, ActiveDirectoryRights.GenericWrite);
                                bool writeProperty = HasAllRights(rights, ActiveDirectoryRights.WriteProperty);
                                bool writeDacl = HasAllRights(rights, ActiveDirectoryRights.WriteDacl);
                                bool writeOwner = HasAllRights(rights, ActiveDirectoryRights.WriteOwner);

                                bool propertyAppliesToGplink =
                                    ace.ObjectType == Guid.Empty || ace.ObjectType == GpoLinkAttributeGuid;

                                bool directWrite = genericAll || genericWrite ||
                                    (writeProperty && propertyAppliesToGplink);

                                bool aclControl = writeDacl || writeOwner;

                                if (!directWrite && !aclControl)
                                    continue;

                                string principal = ResolveSidToName(sid);
                                string category = "";

                                if (directWrite)
                                    category = "Direct GPLink modification";

                                if (aclControl)
                                    category += (category.Length > 0 ? " + " : "") + "ACL/Owner control";

                                Console.WriteLine();
                                Console.WriteLine("    [{0}] {1}",
                                    ace.AccessControlType == AccessControlType.Allow ? "!" : "-", category);
                                Console.WriteLine("        Principal: {0}", principal);
                                Console.WriteLine("        SID: {0}", sid);
                                Console.WriteLine("        Scope: {0}", scope);
                                Console.WriteLine("        Object: {0}", name);
                                Console.WriteLine("        DN: {0}", dn);
                                Console.WriteLine("        Rights: {0}", rights);
                                Console.WriteLine("        ObjectType: {0}", ace.ObjectType);
                                Console.WriteLine("        Inherited: {0}", ace.IsInherited ? "Yes" : "No");

                                if (ace.AccessControlType == AccessControlType.Deny)
                                {
                                    Console.WriteLine("        [!] Deny ACE: avaliar junto das demais ACEs para determinar acesso efetivo.");
                                    denyFindings++;
                                }
                                else
                                {
                                    if (directWrite)
                                        Console.WriteLine("        [!] Pode alterar diretamente o atributo gPLink.");
                                    if (aclControl)
                                        Console.WriteLine("        [!] Controle indireto: pode modificar a DACL ou o Owner do escopo.");
                                    allowFindings++;
                                }
                            }
                        }
                        catch (Exception exInner)
                        {
                            Console.WriteLine("    [-] Nao foi possivel ler a DACL de " + dn + ": " + exInner.Message);
                        }
                    }
                });

                PrintColored(String.Format(
                    "[*] ACEs Allow relevantes: {0} | ACEs Deny relevantes: {1}",
                    allowFindings, denyFindings), ConsoleColor.DarkGray);
            }
            catch (Exception ex)
            {
                PrintColored("[-] Erro ao enumerar permissoes de GPO Link: " + ex.Message, ConsoleColor.Red);
            }
        }

        public static void FindGPOCreators()
        {
            PrintColored("[*] Enumerando permissoes para criar GPOs...", ConsoleColor.Yellow);

            try
            {
                string defaultNC;
                string configurationNC;
                GetGpoNamingContexts(out defaultNC, out configurationNC);

                string policiesDN = "CN=Policies,CN=System," + defaultNC;

                Guid gpoClassGuid = GpoContainerClassGuid;

                int allowFindings = 0;
                int denyFindings = 0;

                using (DirectoryEntry entry = new DirectoryEntry("LDAP://" + policiesDN))
                {
                    AuthorizationRuleCollection rules = entry.ObjectSecurity.GetAccessRules(
                        true,
                        true,
                        typeof(SecurityIdentifier));

                    foreach (AuthorizationRule rule in rules)
                    {
                        ActiveDirectoryAccessRule ace = rule as ActiveDirectoryAccessRule;

                        if (ace == null)
                            continue;

                        string sid = ace.IdentityReference.Value;
                        ActiveDirectoryRights rights = ace.ActiveDirectoryRights;

                        bool createChild = HasAllRights(
                            rights,
                            ActiveDirectoryRights.CreateChild);

                        bool genericAll = HasAllRights(
                            rights,
                            ActiveDirectoryRights.GenericAll);

                        bool writeDacl = HasAllRights(
                            rights,
                            ActiveDirectoryRights.WriteDacl);

                        bool writeOwner = HasAllRights(
                            rights,
                            ActiveDirectoryRights.WriteOwner);

                        bool appliesToAllClasses = ace.ObjectType == Guid.Empty;
                        bool appliesToGpoClass = ace.ObjectType == gpoClassGuid;

                        bool canCreateGpo = createChild &&
                            (appliesToAllClasses || appliesToGpoClass);

                        bool canControlContainer = genericAll &&
                            appliesToAllClasses;

                        bool canModifyDacl = writeDacl &&
                            appliesToAllClasses;

                        bool canModifyOwner = writeOwner &&
                            appliesToAllClasses;

                        bool indirectControl = canModifyDacl || canModifyOwner;

                        if (!canCreateGpo &&
                            !canControlContainer &&
                            !indirectControl)
                        {
                            continue;
                        }

                        string principal = ResolveSidToName(sid);

                        Console.WriteLine();

                        Console.WriteLine(
                            "    [{0}] Permissao relevante no container de GPO",
                            ace.AccessControlType == AccessControlType.Allow ? "!" : "-");

                        Console.WriteLine("        Principal: {0}", principal);
                        Console.WriteLine("        SID: {0}", sid);
                        Console.WriteLine("        Container: CN=Policies,CN=System");
                        Console.WriteLine("        DN: {0}", policiesDN);
                        Console.WriteLine("        Rights: {0}", rights);
                        Console.WriteLine("        ObjectType: {0}", ace.ObjectType);
                        Console.WriteLine("        Inherited: {0}", ace.IsInherited ? "Yes" : "No");

                        if (canCreateGpo)
                        {
                            Console.WriteLine("        Capability: Can Create GPO");

                            if (appliesToAllClasses)
                            {
                                Console.WriteLine(
                                    "        Scope: CreateChild applies to all child object classes");
                            }
                            else
                            {
                                Console.WriteLine(
                                    "        Scope: CreateChild applies specifically to groupPolicyContainer");
                            }
                        }

                        if (canControlContainer)
                        {
                            Console.WriteLine(
                                "        Capability: GenericAll - Full Control on the Policies container");

                            Console.WriteLine(
                                "        [!] This broad permission includes the ability to create GPO child objects.");
                        }

                        if (canModifyDacl)
                        {
                            Console.WriteLine(
                                "        Capability: WriteDacl - Can modify the container DACL");

                            Console.WriteLine(
                                "        [!] Indirect path: may allow granting CreateChild to another principal.");
                        }

                        if (canModifyOwner)
                        {
                            Console.WriteLine(
                                "        Capability: WriteOwner - Can take ownership of the container");

                            Console.WriteLine(
                                "        [!] Indirect path: ownership may allow subsequent DACL modification.");
                        }

                        if (ace.AccessControlType == AccessControlType.Deny)
                        {
                            Console.WriteLine(
                                "        [!] Deny ACE: avaliar junto das demais ACEs e do token do usuario.");

                            denyFindings++;
                        }
                        else
                        {
                            if (canCreateGpo || canControlContainer)
                            {
                                Console.WriteLine(
                                    "        [!] Permissao Allow relacionada a criacao de GPO identificada.");
                            }

                            if (indirectControl)
                            {
                                Console.WriteLine(
                                    "        [!] Controle indireto identificado; nao confirma criacao direta de GPO.");
                            }

                            allowFindings++;
                        }
                    }
                }

                PrintColored(
                    String.Format(
                        "[*] ACEs Allow relevantes: {0} | ACEs Deny relevantes: {1}",
                        allowFindings,
                        denyFindings),
                    ConsoleColor.DarkGray);

                Console.WriteLine(
                    "[*] Nota: a enumeracao identifica ACEs individuais; nao calcula o acesso efetivo combinando grupos, token e precedencia de Deny.");
            }
            catch (Exception ex)
            {
                PrintColored(
                    "[-] Erro ao enumerar criadores de GPO: " + ex.Message,
                    ConsoleColor.Red);
            }
        }

        private static readonly Guid GpoLinkAttributeGuid =
            new Guid("f30e3bbe-9ff0-11d1-b603-0000f80367c1");

        private static readonly Guid GpoContainerClassGuid =
            new Guid("f30e3bc2-9ff0-11d1-b603-0000f80367c1");

        private static void GetGpoNamingContexts(out string defaultNC, out string configurationNC)
        {
            using (DirectoryEntry rootDse = new DirectoryEntry("LDAP://RootDSE"))
            {
                defaultNC = rootDse.Properties["defaultNamingContext"].Value.ToString();
                configurationNC = rootDse.Properties["configurationNamingContext"].Value.ToString();
            }
        }

        private static Dictionary<string, string> GetGpoNameMap(string defaultNC)
        {
            Dictionary<string, string> names =
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            string policiesDN = "CN=Policies,CN=System," + defaultNC;

            using (DirectoryEntry root = new DirectoryEntry("LDAP://" + policiesDN))
            using (DirectorySearcher searcher = new DirectorySearcher(root))
            {
                searcher.Filter = "(objectClass=groupPolicyContainer)";
                searcher.SearchScope = SearchScope.Subtree;
                searcher.PageSize = 500;
                searcher.PropertiesToLoad.Add("name");
                searcher.PropertiesToLoad.Add("displayName");

                using (SearchResultCollection results = searcher.FindAll())
                {
                    foreach (SearchResult result in results)
                    {
                        string guid = GetGpoProperty(result, "name").Trim('{', '}');
                        string displayName = GetGpoProperty(result, "displayName");

                        if (!String.IsNullOrEmpty(guid))
                            names[guid] = String.IsNullOrEmpty(displayName) ? guid : displayName;
                    }
                }
            }

            return names;
        }

        private static void EnumerateGpoScopes(
            string defaultNC,
            string configurationNC,
            Action<SearchResult, string> callback)
        {
            using (DirectoryEntry root = new DirectoryEntry("LDAP://" + defaultNC))
            using (DirectorySearcher searcher = new DirectorySearcher(root))
            {
                searcher.Filter = "(objectCategory=domainDNS)";
                searcher.SearchScope = SearchScope.Base;
                searcher.PageSize = 500;
                AddGpoScopeProperties(searcher);

                using (SearchResultCollection results = searcher.FindAll())
                {
                    foreach (SearchResult result in results)
                        callback(result, "Domain");
                }
            }

            string sitesDN = "CN=Sites," + configurationNC;

            using (DirectoryEntry root = new DirectoryEntry("LDAP://" + sitesDN))
            using (DirectorySearcher searcher = new DirectorySearcher(root))
            {
                searcher.Filter = "(objectCategory=site)";
                searcher.SearchScope = SearchScope.Subtree;
                searcher.PageSize = 500;
                AddGpoScopeProperties(searcher);

                using (SearchResultCollection results = searcher.FindAll())
                {
                    foreach (SearchResult result in results)
                        callback(result, "Site");
                }
            }

            using (DirectoryEntry root = new DirectoryEntry("LDAP://" + defaultNC))
            using (DirectorySearcher searcher = new DirectorySearcher(root))
            {
                searcher.Filter = "(objectCategory=organizationalUnit)";
                searcher.SearchScope = SearchScope.Subtree;
                searcher.PageSize = 500;
                AddGpoScopeProperties(searcher);

                using (SearchResultCollection results = searcher.FindAll())
                {
                    foreach (SearchResult result in results)
                        callback(result, "OU");
                }
            }
        }

        private static void AddGpoScopeProperties(DirectorySearcher searcher)
        {
            searcher.PropertiesToLoad.Add("distinguishedName");
            searcher.PropertiesToLoad.Add("name");
            searcher.PropertiesToLoad.Add("gPLink");
            searcher.PropertiesToLoad.Add("gPOptions");
        }

        private static string GetGpoProperty(SearchResult result, string property)
        {
            if (!result.Properties.Contains(property) || result.Properties[property].Count == 0)
                return "";

            return result.Properties[property][0].ToString();
        }

        private static int GetGpoIntProperty(SearchResult result, string property)
        {
            int value;
            return Int32.TryParse(GetGpoProperty(result, property), out value) ? value : 0;
        }

        private static string ExtractGpoGuid(string dn)
        {
            Match match = Regex.Match(
                dn,
                @"\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?"
            );

            return match.Success ? match.Groups[1].Value : null;
        }


        public static void CreateGPO(string[] args)
        {
            if (args.Length < 2 || args.Length > 3)
            {
                PrintColored("[-] Uso: Strix.exe gpocreate <NomeDaGPO> [Dominio.local]", ConsoleColor.Red);
                return;
            }

            string gpoName = args[1].Trim();
            string domain = args.Length == 3 ? args[2].Trim() : null;

            if (String.IsNullOrWhiteSpace(gpoName))
            {
                PrintColored("[-] Informe um nome valido para a GPO.", ConsoleColor.Red);
                return;
            }

            try
            {
                string defaultNC;
                string configurationNC;
                string server;

                GetGpoDirectoryContext(domain, out defaultNC, out configurationNC, out server);

                string script =
                    "$ErrorActionPreference = 'Stop'; " +
                    "try { " +
                    "Import-Module GroupPolicy -ErrorAction Stop; " +
                    "$gpo = New-GPO -Name " + EscapePowerShellString(gpoName) +
                    " -Domain " + EscapePowerShellString(domain ?? GetDomainFromNamingContext(defaultNC)) +
                    " -Server " + EscapePowerShellString(server) +
                    " -ErrorAction Stop; " +
                    "$gpo | Select-Object DisplayName, Id, GpoStatus | ConvertTo-Json -Compress; " +
                    "exit 0; " +
                    "} catch { " +
                    "[Console]::Error.WriteLine($_.Exception.Message); " +
                    "exit 1; " +
                    "}";

                PrintColored("[*] Criando GPO no dominio...", ConsoleColor.Yellow);
                Console.WriteLine("    Nome: " + gpoName);
                Console.WriteLine("    Dominio: " + GetDomainFromNamingContext(defaultNC));
                Console.WriteLine("    Domain Controller: " + server);

                string output;
                string error;

                bool success = ExecuteGroupPolicyPowerShell(script, out output, out error);

                if (!success)
                {
                    PrintColored("[-] Falha ao criar GPO.", ConsoleColor.Red);

                    if (!String.IsNullOrWhiteSpace(error))
                        Console.WriteLine("    Erro: " + error);

                    return;
                }

                PrintColored("[+] GPO criada com sucesso!", ConsoleColor.Green);
                Console.WriteLine();
                Console.WriteLine("    Resultado:");
                Console.WriteLine("    " + output);
            }
            catch (Exception ex)
            {
                PrintColored("[-] Erro ao criar GPO: " + ex.Message, ConsoleColor.Red);
            }
        }

        public static void CreateGPOLink(string[] args)
        {
            if (args.Length < 4 || args.Length > 5)
            {
                PrintColored(
                    "[-] Uso: Strix.exe gpocreatelink <GPO> <Dominio.local> <domain|ou|site> [NomeOuDN]",
                    ConsoleColor.Red);
                return;
            }

            string gpoName = args[1].Trim();
            string domain = args[2].Trim();
            string scopeType = args[3].Trim().ToLower();
            string targetName = args.Length == 5 ? args[4].Trim() : "";

            if (String.IsNullOrWhiteSpace(gpoName) || String.IsNullOrWhiteSpace(domain))
            {
                PrintColored("[-] Nome da GPO e dominio sao obrigatorios.", ConsoleColor.Red);
                return;
            }

            if (scopeType != "domain" && scopeType != "ou" && scopeType != "site")
            {
                PrintColored("[-] Tipo de destino invalido. Utilize domain, ou ou site.", ConsoleColor.Red);
                return;
            }

            if (scopeType == "domain" && args.Length != 4)
            {
                PrintColored("[-] Para o escopo domain, nao informe um destino adicional.", ConsoleColor.Red);
                return;
            }

            if (scopeType != "domain" && String.IsNullOrWhiteSpace(targetName))
            {
                PrintColored("[-] Informe o nome ou DN da OU/Site.", ConsoleColor.Red);
                return;
            }

            try
            {
                string defaultNC;
                string configurationNC;
                string server;

                GetGpoDirectoryContext(domain, out defaultNC, out configurationNC, out server);

                string targetDN = ResolveGpoLinkTarget(
                    scopeType,
                    targetName,
                    defaultNC,
                    configurationNC,
                    server);

                if (String.IsNullOrEmpty(targetDN))
                {
                    PrintColored("[-] Nao foi possivel resolver o destino informado.", ConsoleColor.Red);
                    return;
                }

                string script =
                    "$ErrorActionPreference = 'Stop'; " +
                    "try { " +
                    "Import-Module GroupPolicy -ErrorAction Stop; " +
                    "$link = New-GPLink " +
                    "-Name " + EscapePowerShellString(gpoName) + " " +
                    "-Target " + EscapePowerShellString(targetDN) + " " +
                    "-Domain " + EscapePowerShellString(domain) + " " +
                    "-Server " + EscapePowerShellString(server) + " " +
                    "-LinkEnabled Yes " +
                    "-ErrorAction Stop; " +
                    "[PSCustomObject]@{ " +
                    "DisplayName = $link.DisplayName; " +
                    "GpoId = $link.GpoId; " +
                    "Target = " + EscapePowerShellString(targetDN) + "; " +
                    "LinkEnabled = 'Yes' " +
                    "} | ConvertTo-Json -Compress; " +
                    "exit 0; " +
                    "} catch { " +
                    "[Console]::Error.WriteLine($_.Exception.Message); " +
                    "exit 1; " +
                    "}";

                PrintColored("[*] Criando vinculo de GPO...", ConsoleColor.Yellow);
                Console.WriteLine("    GPO: " + gpoName);
                Console.WriteLine("    Dominio: " + domain);
                Console.WriteLine("    Escopo: " + scopeType);
                Console.WriteLine("    Target DN: " + targetDN);
                Console.WriteLine("    Domain Controller: " + server);

                string output;
                string error;

                bool success = ExecuteGroupPolicyPowerShell(script, out output, out error);

                if (!success)
                {
                    PrintColored("[-] Falha ao criar vinculo da GPO.", ConsoleColor.Red);

                    if (!String.IsNullOrWhiteSpace(error))
                        Console.WriteLine("    Erro: " + error);

                    return;
                }

                PrintColored("[+] Vinculo criado com sucesso!", ConsoleColor.Green);
                Console.WriteLine();
                Console.WriteLine("    Resultado:");
                Console.WriteLine("    " + output);
            }
            catch (Exception ex)
            {
                PrintColored("[-] Erro ao criar GPO Link: " + ex.Message, ConsoleColor.Red);
            }
        }



        private static void GetGpoDirectoryContext(
            string domain,
            out string defaultNC,
            out string configurationNC,
            out string server)
        {
            string rootPath = String.IsNullOrWhiteSpace(domain)
                ? "LDAP://RootDSE"
                : "LDAP://" + domain + "/RootDSE";

            using (DirectoryEntry rootDse = new DirectoryEntry(rootPath))
            {
                defaultNC = rootDse.Properties["defaultNamingContext"].Value.ToString();
                configurationNC = rootDse.Properties["configurationNamingContext"].Value.ToString();
                server = rootDse.Properties["dnsHostName"].Value.ToString();
            }
        }

        private static string GetDomainFromNamingContext(string namingContext)
        {
            string[] parts = namingContext.Split(',');
            List<string> domainParts = new List<string>();

            foreach (string part in parts)
            {
                if (part.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                    domainParts.Add(part.Substring(3));
            }

            return String.Join(".", domainParts.ToArray());
        }

        private static string EscapePowerShellString(string value)
        {
            return "'" + value.Replace("'", "''") + "'";
        }

        private static string EscapeLdapFilterValue(string value)
        {
            return value.Replace("\\", "\\5c")
                        .Replace("*", "\\2a")
                        .Replace("(", "\\28")
                        .Replace(")", "\\29")
                        .Replace("\0", "\\00");
        }

        private static bool ExecuteGroupPolicyPowerShell(
            string script,
            out string output,
            out string error)
        {
            output = "";
            error = "";

            string encodedScript = Convert.ToBase64String(
                System.Text.Encoding.Unicode.GetBytes(script));

            System.Diagnostics.ProcessStartInfo startInfo =
                new System.Diagnostics.ProcessStartInfo();

            startInfo.FileName = "powershell.exe";
            startInfo.Arguments = "-NoProfile -NonInteractive -EncodedCommand " + encodedScript;
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;

            using (System.Diagnostics.Process process =
                new System.Diagnostics.Process())
            {
                process.StartInfo = startInfo;
                process.Start();

                output = process.StandardOutput.ReadToEnd();
                error = process.StandardError.ReadToEnd();

                process.WaitForExit();

                return process.ExitCode == 0;
            }
        }

        private static string DiscoverDomainController(string domain)
        {
            DirectoryContext context = new DirectoryContext(
                DirectoryContextType.Domain,
                domain);

            using (Domain currentDomain = Domain.GetDomain(context))
            using (DomainController controller = currentDomain.FindDomainController())
            {
                return controller.Name;
            }
        }


            public static void CreateGPOScheduledTask(string[] args)
            {
                if (args.Length != 5)
                {
                    Console.WriteLine("Uso: strix.exe gposcheduletask <GPO> <cmd|powershell> <machine|user> \"<comando>\"");
                    return;
                }

                string gpoName = args[1];
                string commandType = args[2].ToLower();
                string scope = args[3].ToLower();
                string command = args[4].Trim();


                if (commandType != "cmd" && commandType != "powershell")
                {
                    Console.WriteLine("[-] Tipo invalido. Use cmd ou powershell.");
                    return;
                }

                if (scope != "machine" && scope != "user")
                {
                    Console.WriteLine("[-] Escopo invalido. Use machine ou user.");
                    return;
                }

                try
                {
                    string defaultNC;
                    string configurationNC;
                    string server;

                    GetGpoDirectoryContext(null, out defaultNC, out configurationNC, out server);

                    string gpoGuid = null;
                    string gpoFileSysPath = null;

                    using (DirectoryEntry entry = new DirectoryEntry("LDAP://" + server + "/" + defaultNC))
                    using (DirectorySearcher searcher = new DirectorySearcher(entry))
                    {
                        searcher.Filter = "(&(objectClass=groupPolicyContainer)(displayName=" +
                            EscapeLdapFilterValue(gpoName) + "))";

                        searcher.PropertiesToLoad.Add("name");
                        searcher.PropertiesToLoad.Add("gPCFileSysPath");

                        SearchResult result = searcher.FindOne();

                        if (result == null)
                        {
                            Console.WriteLine("[-] GPO nao encontrada: " + gpoName);
                            return;
                        }

                        gpoGuid = result.Properties["name"].ToString();
                        gpoFileSysPath = result.Properties["gPCFileSysPath"].ToString();
                    }

                    string scopeDirectory = scope == "machine" ? "Machine" : "User";

                    string outputDirectory = System.IO.Path.Combine(
                        gpoFileSysPath,
                        scopeDirectory,
                        "Preferences",
                        "ScheduledTasks"
                    );

                    System.IO.Directory.CreateDirectory(outputDirectory);

                    string executable;
                    string arguments;

                    if (commandType == "cmd")
                    {
                        executable = @"C:\Windows\System32\cmd.exe";
                        arguments = "/c " + command;
                    }
                    else
                    {
                        executable = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
                        arguments = "-NoProfile -NonInteractive -Command \"" + command + "\"";
                    }

                    string taskName = "StrixCommand";
                    string uid = "{" + Guid.NewGuid().ToString().ToUpper() + "}";
                    string changed = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                    string startBoundary = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss");

                    // Define conta e LogonType conforme escopo
                    string runAsAccount = scope == "machine" ? "S-1-5-18" : @"%LogonDomain%\%LogonUser%";
                    string principalUserId = scope == "machine" ? "S-1-5-18" : @"%LogonDomain%\%LogonUser%";
                    string logonTypeValue = scope == "machine" ? "S4U" : "InteractiveToken";

                    string xmlTemplate = @"<?xml version=""1.0"" encoding=""utf-8""?>
            <ScheduledTasks clsid=""{CC63F200-7309-4ba0-B154-A71CD118DBCC}"">
                  <TaskV2 clsid=""{D8896631-B747-47a7-84A6-C155337F3BC8}"" name="""" image=""0"" changed="""" uid="""">
                        <Properties action=""C"" name="""" runAs="""" logonType="""">
                              <Task version=""1.2"">
                                    <RegistrationInfo>
                                          <Author>Strix</Author>
                                          <Description>Strix Command task</Description>
                                    </RegistrationInfo>
                                    <Principals>
                                          <Principal id=""Author"">
                                                <UserId></UserId>
                                                <LogonType></LogonType>
                                                <RunLevel>HighestAvailable</RunLevel>
                                          </Principal>
                                    </Principals>
                                    <Settings>
                                          <IdleSettings>
                                                <Duration>PT10M</Duration>
                                                <WaitTimeout>PT1H</WaitTimeout>
                                                <StopOnIdleEnd>true</StopOnIdleEnd>
                                                <RestartOnIdle>false</RestartOnIdle>
                                          </IdleSettings>
                                          <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                                          <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
                                          <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
                                          <AllowHardTerminate>true</AllowHardTerminate>
                                          <StartWhenAvailable>false</StartWhenAvailable>
                                          <AllowStartOnDemand>true</AllowStartOnDemand>
                                          <Enabled>true</Enabled>
                                          <Hidden>false</Hidden>
                                          <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
                                          <Priority>7</Priority>
                                    </Settings>
                                    <Triggers>
                                          <TimeTrigger>
                                                <StartBoundary></StartBoundary>
                                                <Enabled>true</Enabled>
                                                <Repetition>
                                                      <Interval>PT5M</Interval>
                                                      <Duration>P1D</Duration>
                                                      <StopAtDurationEnd>false</StopAtDurationEnd>
                                                </Repetition>
                                          </TimeTrigger>
                                    </Triggers>
                                    <Actions Context=""Author"">
                                          <Exec>
                                                <Command></Command>
                                                <Arguments></Arguments>
                                          </Exec>
                                    </Actions>
                              </Task>
                        </Properties>
                  </TaskV2>
            </ScheduledTasks>";

                    System.Xml.XmlDocument document = new System.Xml.XmlDocument();
                    document.LoadXml(xmlTemplate);

                    System.Xml.XmlElement taskV2 = (System.Xml.XmlElement)document.SelectSingleNode("//TaskV2");
                    taskV2.SetAttribute("name", taskName);
                    taskV2.SetAttribute("changed", changed);
                    taskV2.SetAttribute("uid", uid);

                    System.Xml.XmlElement props = (System.Xml.XmlElement)document.SelectSingleNode("//Properties");
                    props.SetAttribute("name", taskName);
                    props.SetAttribute("runAs", runAsAccount);
                    props.SetAttribute("logonType", logonTypeValue);

                    document.SelectSingleNode("//UserId").InnerText = principalUserId;
                    document.SelectSingleNode("//LogonType").InnerText = logonTypeValue;
                    document.SelectSingleNode("//StartBoundary").InnerText = startBoundary;
                    document.SelectSingleNode("//Command").InnerText = executable;
                    document.SelectSingleNode("//Arguments").InnerText = arguments;

                    string outputFile = System.IO.Path.Combine(outputDirectory, "ScheduledTasks.xml");

                    System.Xml.XmlWriterSettings writerSettings = new System.Xml.XmlWriterSettings();
                    writerSettings.Encoding = new System.Text.UTF8Encoding(false);
                    writerSettings.Indent = true;
                    writerSettings.IndentChars = "\t";
                    writerSettings.OmitXmlDeclaration = false;

                    using (System.Xml.XmlWriter writer = System.Xml.XmlWriter.Create(outputFile, writerSettings))
                    {
                        document.Save(writer);
                    }


                    Console.WriteLine("[+] ScheduledTasks.xml criado com sucesso em: " + outputFile);
                    Console.WriteLine("    GPO: " + gpoName);
                    Console.WriteLine("    GUID: " + gpoGuid);
                    Console.WriteLine("    Escopo: " + scopeDirectory);
                    Console.WriteLine("    Tipo: " + commandType);
                    Console.WriteLine("    Comando: " + command);
                    Console.WriteLine("    Arquivo: " + outputFile);
                    Console.WriteLine("[*] Alteração realizada no SYSVOL.");                  

                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] Erro ao criar GPO Scheduled Task: " + ex.Message);
                }
            }

        private static string ResolveGpoLinkTarget(
            string scopeType,
            string targetName,
            string defaultNC,
            string configurationNC,
            string server)
        {
            if (scopeType == "domain")
                return defaultNC;

            string expectedClass = scopeType == "ou"
                ? "organizationalUnit"
                : "site";

            if (String.IsNullOrWhiteSpace(targetName))
                throw new ArgumentException("Destino nao informado.");

            if (targetName.Contains("=") && targetName.Contains(","))
            {
                using (DirectoryEntry entry =
                    new DirectoryEntry("LDAP://" + server + "/" + targetName))
                {
                    entry.RefreshCache(new string[] { "objectClass" });

                    foreach (object objectClass in entry.Properties["objectClass"])
                    {
                        if (String.Equals(
                            objectClass.ToString(),
                            expectedClass,
                            StringComparison.OrdinalIgnoreCase))
                        {
                            return targetName;
                        }
                    }
                }

                throw new InvalidOperationException(
                    "O DN informado nao corresponde ao tipo de escopo solicitado.");
            }

            string searchBase = scopeType == "ou"
                ? defaultNC
                : "CN=Sites," + configurationNC;

            string filter =
                "(&(objectClass=" + expectedClass + ")" +
                "(name=" + EscapeLdapFilterValue(targetName) + "))";

            using (DirectoryEntry root =
                new DirectoryEntry("LDAP://" + server + "/" + searchBase))
            using (DirectorySearcher searcher =
                new DirectorySearcher(root))
            {
                searcher.Filter = filter;
                searcher.SearchScope = SearchScope.Subtree;
                searcher.PageSize = 100;
                searcher.PropertiesToLoad.Add("distinguishedName");

                using (SearchResultCollection results = searcher.FindAll())
                {
                    if (results.Count == 0)
                        throw new InvalidOperationException(
                            "Destino nao encontrado: " + targetName);

                    if (results.Count > 1)
                        throw new InvalidOperationException(
                            "Mais de um destino encontrado. Informe o DN completo.");

                    return results[0].Properties["distinguishedName"][0].ToString();
                }
            }
        }
    }
}
