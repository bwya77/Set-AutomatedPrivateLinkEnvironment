# Overview
A common and recommended security practice is only allowing access to an Azure Storage Account via a whitelisted IP address. While this is generally a good idea, a problem arises when you need an Azure Automation Account to access one of these Storage Accounts. Currently, even if you whitelist an entire Azure region, your automation runbook will fail to connect to your Storage Account. Instead, you must use an Azure Private Link to connect Azure Automation to your PaaS Azure Resources securely, but “in the current implementation of Private Link, Automation account cloud jobs cannot access Azure resources that are secured using private endpoint. For example, Azure Key Vault, Azure SQL, Azure Storage account, etc. To workaround this, use a [Hybrid Runbook Worker](https://learn.microsoft.com/en-us/azure/automation/automation-hybrid-runbook-worker) instead. Hence, on-premises VMs are supported to run Hybrid Runbook Workers against an Automation Account with Private Link enabled.” [^1]

This configuration isn’t as simple as creating or deploying a traditional Azure Runbook; you must create private endpoints, subnets, DNS zones, hybrid worker groups, and more. I wanted to make a PowerShell script that anyone could run, and it would generate everything for you from start to finish, so in the end, it would be working out of the box without additional configuration needed. This includes installing PowerShell Core on the Hybrid Runbook Worker. The diagram below gives an architectural overview of the deployment and configuration.

> [!NOTE]
> Private Link support with Azure Automation is available only in Azure Commercial and Azure US Government clouds.

 ```mermaid
flowchart TB
 subgraph subGraph0["Azure Resources"]
        AA["Automation Account:<br>Basic Plan"]
        MI2["Automation Account<br>Managed Identity"]
        ST["Storage Account:<br>Standard_LRS"]
  end
 subgraph subGraph1["Hybrid Worker Components"]
        VM["Hybrid Worker VM:<br>Windows Server 2019"]
        NSG1["Network Security Group"]
        HWG["Hybrid Worker Group"]
        MI1["VM System-assigned<br>Managed Identity"]
  end
 subgraph subGraph2["Private Endpoint Subnet"]
        PE2["Private Endpoint -<br>Automation Account"]
        DNS2["privatelink.azure-automation.net"]
        PE1["Private Endpoint -<br>Storage Table"]
        DNS1["privatelink.table.core.windows.net"]
  end
 subgraph subGraph3["Virtual Network"]
        subGraph1
        subGraph2
  end
 subgraph subGraph4["Resource Group"]
        subGraph0
        subGraph3
  end
    VM --> NSG1 & MI1 & HWG
    HWG -- Private Link --> PE2
    MI1 -- Private Link --> PE1
    PE1 <-- Private Link --> ST
    PE2 <-- Private Link --> AA
    AA --> MI2
    MI2 -- Private Link --> PE1
    DNS1 -.-> PE1
    DNS2 -.-> PE2
    subGraph1 --> subGraph3

     AA:::azure
     MI2:::identity
     ST:::azure
     VM:::azure
     NSG1:::security
     HWG:::azure
     MI1:::identity
     PE2:::security
     DNS2:::network
     PE1:::security
     DNS1:::network
    classDef azure fill:#0078D4,color:#fff
    classDef security fill:#ED7D31,color:#fff
    classDef network fill:#00BCF2,color:#fff
    classDef identity fill:#7FBA00,color:#fff



```

The script handles everything from creating the Virtual Network with proper subnet configuration, setting up Private Endpoints and DNS zones, configuring a Hybrid Worker VM, and implementing Managed Identity authentication. You can deploy this entire environment with a single PowerShell script rather than spending hours clicking through the Azure portal or writing multiple scripts.

**Key features of this deployment**:

- Complete network isolation with Private Link and Private Endpoints
- Automated DNS configuration for private networking
- Hybrid Worker VM setup with proper security configuration
- System-assigned Managed Identity implementation for secure authentication
- Zero public endpoint exposure for Storage Account
- Proper RBAC assignments for least privileged access
- Network Security Group configuration for the Hybrid Worker VM
- Tags all the resources it deploys for easy identification

> [!NOTE] 
> While the script deploys the hybrid worker VM with a public IP address, you can remove the public IP address from the hybrid worker upon completion. I added it so I could install `Pwsh7` and set up Bastion access.

## Pre-requisites
1. [Az Module](https://learn.microsoft.com/en-us/powershell/azure/new-azureps-module-az?view=azps-13.0.0)
	1. Az.Network
	2. Az.Storage
	3. Az.Automation
	4. Az.Compute
	5. Az.OperationalInsights
2. Azure Subscription
3. Proper Azure Permissions to create and manage resources within a subscription
# Script Execution and Functional Overview
## Deployment

1. Download the current version of the PowerShell script [here](https://github.com/bwya77/Set-AutomatedPrivateLinkEnvironment/tree/main).
2. Save the script somewhere we can reference later. I recommend a folder called `Scripts` on the root of `C:\`
3. Next, we need to create the `param` block for our deployment. This is the step where you name your resources and specify the location of them. Four parameters have default values (`vnetAddressPrefix`, `PrivateEndpointSubnetAddressPrefix`, `HybridWorkerSUbnetAddressPrefix` and `Tags`)
	1. The only items it will not create if they are present are the **Automation Account** and **Resource Group**. Everything else will not check to see if it's already present before creation.
	2. **vnetAddressPrefix** has a default value of 10.0.0.0/16
	3. **PrivateEndpointSUbnetAddressPrefix** has a default value of 10.0.1.0/24
	4. **HybridWorkerSubnetAddressPrefix** has a default value of 10.0.2.0/24
	5. **Tags** has a default value of:
``` powershell
"Automation" = "HybridWorker"
"Department" = "DevOps"
```

```powershell
$params = @{
    ResourceGroupName      = "rg-hybridRW"
    Location               = "northcentralus"
    StorageAccountName     = "sahybridrw" + (Get-Random)
    AutomationAccountName  = "StorageAccountName"
    VirtualNetworkName     = "vnet-hybridRW"
    VMName                 = "vm-hybridRW"
    AdminUsername          = "adminuser"
    AdminPassword          = (ConvertTo-SecureString "WeMuSTChAng3!Plz" -AsPlainText -Force)
    RunbookWorkerGroupName = "hybridRWgroup"
    TableName              = "demotable"
    Verbose                = $true
}
```
4. Now that we have specified deployment, open a PowerShell terminal and navigate to the location where you saved the script from step 1.
![[/src/CleanShot 2024-12-30 at 11.54.31.png]]
5. Next, let’s load our `$params` block from earlier 
![[CleanShot 2024-12-30 at 11.58.39.png]]
6. Now we can dot source our PowerShell script with the `$params` values
![[CleanShot 2024-12-30 at 12.02.54.png]]
7. The first thing the script will do will be to check that you have the correct modules installed, if not it will download them and then load them into memory. 
8. Next, it will launch a web login for you to log into Azure with.
![[CleanShot 2024-12-30 at 12.06.40.png]]
9. If you have multiple subscriptions, it will prompt you which subscription you want to deploy into
![[CleanShot 2024-12-30 at 12.09.22 1.png]]
10. After that, since we had verbose messaging turned on, we can see it creating resources
![[CleanShot 2024-12-30 at 12.10.33.png]]
## Testing
1. Once it’s complete, I can navigate to the Azure Portal and see everything that it deployed.
![[CleanShot 2024-12-30 at 13.01.14.png]]
2. If I sign into the Hybrid Runbook worker using Bastion (the reason I gave this machine a public IP) I can go to `C:\` and see that PowerShell Core 7 has been installed. 
![[CleanShot 2024-12-30 at 13.04.07.png]]
3. Next, I will create a test table entry in my table. 
![[CleanShot 2024-12-30 at 13.17.02.png]]
4. Next, I will go to my Azure Automation Account and create a new test runbook to ensure I have access to the Storage Table
![[CleanShot 2024-12-30 at 13.19.34 1.png]]
5. Next, I will paste the following PowerShell code for the runbook content:
	1. Make sure to change the Storage Account name from `sahybridrw1226660012` to your Storage Account name.
	2. Make sure to change the Table name from `demotable` to your Table’s name.
```powershell
Install-Module Az -Force
function Get-AZTableEntityAll {
    [CmdletBinding()]  # This enables -Verbose support
    param (
        [Parameter(Mandatory)]
        [string] $StorageAccount,
        [Parameter(Mandatory)]
        [string] $TableName,
        [string] $SASToken,
        [string] $AccessKey,
        [string] $AzToken,
        [string] $Filter
    )

    Write-Verbose "Starting Get-AZTableEntityAll for table '$TableName' in storage account '$StorageAccount'"
    
    $version = "2022-11-02"
    $resource = "$TableName"
    $GMTTime = (Get-Date).ToUniversalTime().toString('R')
    $stringToSign = "$GMTTime`n/$storageAccount/$resource"
    
    Write-Verbose "Building authentication headers"
    Write-Debug "String to sign: $stringToSign"
    
    # Create headers based on authentication method
    $headers = @{
        'x-ms-date'    = $GMTTime
        "x-ms-version" = $version
        Accept         = "application/json;odata=fullmetadata"
    }

    if ($AccessKey) {
        Write-Verbose "Using AccessKey authentication"
        $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
        $hmacsha.key = [Convert]::FromBase64String($accesskey)
        $signature = $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToSign))
        $signature = [Convert]::ToBase64String($signature)
        $headers.Authorization = "SharedKeyLite " + $StorageAccount + ":" + $signature
    }

    # Build the URL
    $table_url = "https://$StorageAccount.table.core.windows.net/$resource"
    Write-Verbose "Base table URL: $table_url"

    if ($Filter) {
        Write-Verbose "Applying filter: $Filter"
        $table_url = $table_url + '?$filter=' + [uri]::EscapeDataString($filter)
        Write-Debug "URL with filter: $table_url"
    }

    if ($SASToken) {
        Write-Verbose "Using SAS Token authentication"
        $headers.remove('Authorization')
        $table_url = $table_url + '?' + $SASToken
    }
    elseif ($AzToken) {
        Write-Verbose "Using Azure AD Token authentication"
        $headers.Authorization = "Bearer " + $AzToken
    }

    Write-Verbose "Starting initial data retrieval"
    $totalRecords = 0
    $pageCount = 1

    try {
        Write-Progress -Activity "Retrieving table entities" -Status "Page $pageCount" -PercentComplete 0
        $item = Invoke-WebRequest -Method GET -Uri $table_url -Headers $headers -UseBasicParsing -ErrorAction Stop
        
        $pageData = ($item.content | ConvertFrom-JSON).Value
        $totalRecords += $pageData.Count
        Write-Verbose "Retrieved $($pageData.Count) records in page $pageCount"
        $pageData

        while ($item.headers.keys -contains 'x-ms-continuation-NextRowKey' -and 
               $item.headers.keys -contains 'x-ms-continuation-NextPartitionKey') {
            
            $NextRowKey = $item.headers.'x-ms-continuation-NextRowKey'
            $NextPartitionKey = $item.headers.'x-ms-continuation-NextPartitionKey'
            Write-Debug "Next Partition Key: $NextPartitionKey, Next Row Key: $NextRowKey"
            
            Clear-Variable item
            if ($filter) {
                $NewURL = ($table_url + '&NextPartitionKey=' + $NextPartitionKey + '&NextRowKey=' + $NextRowKey)
            }
            else {
                $NewURL = ($table_url + '?NextPartitionKey=' + $NextPartitionKey + '&NextRowKey=' + $NextRowKey)
            }
            
            Write-Verbose "Retrieving page $($pageCount + 1)"
            Write-Progress -Activity "Retrieving table entities" -Status "Page $($pageCount + 1)" -PercentComplete (($pageCount % 100) * 1)
            
            $item = Invoke-WebRequest -Method GET -Uri $NewURL -Headers $headers -UseBasicParsing -ErrorAction Stop
            $pageData = ($item.content | ConvertFrom-JSON).Value
            $totalRecords += $pageData.Count
            Write-Verbose "Retrieved $($pageData.Count) records in page $($pageCount + 1)"
            $pageData
            
            Clear-Variable NextPartitionKey, NextRowKey
            $pageCount++
            Start-Sleep -milliseconds 200
        }
    }
    catch {
    Write-Error "Error retrieving data from Azure Table: $($_.Exception.Message)"
    Write-Verbose "Status Code: $($_.Exception.Response.StatusCode.value__)"
    Write-Verbose "Status Description: $($_.Exception.Response.StatusDescription)"
    Write-Verbose "Request URL: $table_url"
    Write-Verbose "Headers used:"
    $headers.GetEnumerator() | ForEach-Object {
        Write-Verbose "  $($_.Key): $($_.Value)"
    }
    throw $_
    }
    finally {
        Write-Progress -Activity "Retrieving table entities" -Completed
        Write-Verbose "Operation completed. Total records retrieved: $totalRecords across $pageCount pages"
    }
}
Connect-AzAccount -Identity
$AzToken = (Get-AzAccessToken -ResourceUrl "https://sahybridrw1226660012.table.core.windows.net").Token

Get-AZTableEntityAll -StorageAccount 'sahybridrw1226660012' -TableName 'demotable' -AzToken $AzToken -Verbose

```


> [!NOTE] 
> The first line is to install the Az module. We only need to do this once to install the module and then all other runbooks will be able to use the module. This is not part of the original build out script because the runbook runs as the `system` context. 

7. When you test the runbook, select the Hybrid Worker for it to run on. 
![[CleanShot 2024-12-30 at 13.24.35.png]]
8. Once the runbook completes running, we can see that it was able to retrieve my table data. 
![[CleanShot 2024-12-30 at 13.31.16 1.png]]
9. Done! Reminder that you can delete or disassociate the public IP of the hybrid worker if you’d like. 
___
# Sources 
[^1]: https://learn.microsoft.com/en-us/azure/automation/how-to/private-link-security#limitations
