$Banner = @"
   _____ _               _               _____  _  _______ 
  / ____| |             | |             |  __ \| |/ /_   _|
 | (___ | |__   __ _  __| | _____      _| |__) | ' /  | |  
  \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /  ___/|  <   | |  
  ____) | | | | (_| | (_| | (_) \ V  V /| |    | . \ _| |_ 
 |_____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_|    |_|\_\_____|

         ShadowPKI — ADCS Recon & Vulnerability Scanner
"@

function ESC-1 {

    # Ignora SIDs específicos (By Desing)
    $AllowedRIDs = @(
        "18",  # SYSTEM SID
        "512", # Domain Admins SID
        "519"  # Enterprise Admins SID
    )

    $TargetEKUs = @(
        '1.3.6.1.5.5.7.3.0',  # Any Purpose
        '1.3.6.1.5.5.7.3.2'   # Client Authentication
    )

    $EnrollMask = 0x00000002
    $AutoEnrollMask = 0x00000010

    # Verifica os Templates de certificado no domínio
    $root = [ADSI]"LDAP://RootDSE"
    $configDN = $root.configurationNamingContext
    $path = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"

    $templates = ([ADSI]$path).psbase.Children |
        Where-Object { $_."msPKI-Enrollment-Flag" -ne $null -and $_."msPKI-Enrollment-Flag" -ne 0 }

    $VulnCount = 0

    foreach ($template in $templates) {

        $name = $template.displayName
        if (-not $name) { $name = $template.Name }

        # Verifica no templates se o SAN está habilitado
        $NameFlags = [int]$template.'msPKI-Certificate-Name-Flag'[0]
        $HasSAN = ($NameFlags -band 1) -ne 0 -or ($NameFlags -band 2) -ne 0 -or ($NameFlags -band 4) -ne 0

        # Verifica EKUs especificos em cada template
        $EKUs = $template.'pKIExtendedKeyUsage'
        $HasTargetEKU = $false

        if ($EKUs) {
            $HasTargetEKU = ($EKUs | Where-Object { $TargetEKUs -contains $_ }).Count -gt 0
        }

        # Verifica as ACEs dos templates de certificado
        $BadPerms = @()

        try {
            $Security = $template.psbase.ObjectSecurity
            $ACL = $Security.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
        } catch {
            continue
        }

        foreach ($rule in $ACL) {

            if (($rule.ActiveDirectoryRights.value__ -band $EnrollMask) -or
                ($rule.ActiveDirectoryRights.value__ -band $AutoEnrollMask)) {

                try {
                    $SID = ($rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])).Value
                } catch {
                    continue
                }

                $RID = $SID.Split('-')[-1]

                if ($AllowedRIDs -notcontains $RID) {
                    $BadPerms += $SID
                }
            }
        }

        # Identifica template vulnerável (match de ESC1)
        if ($HasSAN -and $HasTargetEKU -and $BadPerms.Count -gt 0) {
            $VulnCount++
            Write-Host "|─────────────────────────────────────────────────────────────────────────────────────────|"
            Write-Host "[!] TEMPLATE VULNERÁVEL (ESC1 DETECTADO) → Template: $name" -ForegroundColor Red
            Write-Host "[+] SAN habilitado"
            Write-Host "[+] EKU perigosa detectada: 1.3.6.1.5.5.7.3.2 (Client Authentication)"
            Write-Host "[+] Permissões indevidas:"

            foreach ($sid in $BadPerms) {
                try {
                    $ResolvedName = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
                } catch {
                    $ResolvedName = "Unknown"
                }
                Write-Host "     → $sid ($ResolvedName)" -ForegroundColor Yellow
            }

            Write-Host "|─────────────────────────────────────────────────────────────────────────────────────────|"
            Write-Host ""
        }
    }

    if ($VulnCount -eq 0) {
        Write-Host "`n[-] Nenhum template vulnerável a ESC1 encontrado.`n" -ForegroundColor Green
    } else {
        Write-Host "`n[!] Total detectado: $VulnCount templates vulneráveis a ESC1.`n" -ForegroundColor Yellow
    }
}

function Show-Menu {
    while ($true) {
        Clear-Host
        Write-Host "|─────────────────────────────────────────────────────────────────────────────────────────|`n"
        Write-Host "`n$Banner" -ForegroundColor Cyan
        Write-Host "|─────────────────────────────────────────────────────────────────────────────────────────|`n"
        Write-Host "[1] Enumerar Templates de certificado vulneráveis"
        Write-Host "[2] Sair"
        Write-Host "|─────────────────────────────────────────────────────────────────────────────────────────|"

        $choice = Read-Host "Digite um número"

        switch ($choice) {
            '1' {
                # s
                ESC-1
                return
            }

            '2' {
                Write-Host "Saindo..."
                return
            }

            default {
                Write-Host "Opção inválida!" -ForegroundColor Red
                Pause
            }
        }
    }
}

Show-Menu
