using System;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Threading;

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
            PrintColored("[*] Cacando Foreign Principals...", ConsoleColor.Yellow);
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
                                    if (accessorSid == "S-1-3-0" || // CREATOR OWNER
                                        accessorSid == "S-1-5-18" || // SYSTEM
                                        accessorSid == "S-1-5-32-544" || // Administrators
                                        accessorSid == "S-1-5-10" || // SELF
                                        accessorSid.EndsWith("-512") || // Domain Admins
                                        accessorSid.EndsWith("-519") || // Enterprise Admins
                                        accessorSid.EndsWith("-518") || // Schema Admins
                                        accessorSid.EndsWith("-544"))
                                    {
                                        continue;
                                    }

                                    string rights = adRule.ActiveDirectoryRights.ToString();
                                    
                                    // Critério rigoroso para escrita em GPO: exige controle total ou alteração de DACL/Owner
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
    }
}
