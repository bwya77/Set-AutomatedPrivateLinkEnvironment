<#
.SYNOPSIS
Sets up a private link environment in Azure with Storage Account, Automation Account, and Hybrid Worker VM.

.DESCRIPTION
This script automates the setup of a private link environment in Azure. It creates and configures:
- Resource Group with specified tags
- Virtual Network with private endpoint and hybrid worker subnets
- Storage Account with private endpoint and table storage
- Azure Automation Account with private endpoint 
- Hybrid Worker VM with PowerShell 7
- Private DNS zones and network links for connectivity
- Required role assignments and permissions
- Network security configuration and firewall rules

.PARAMETER ResourceGroupName
The name of the Resource Group to create or use.

.PARAMETER Location
The Azure region where resources will be deployed.

.PARAMETER StorageAccountName 
The name of the Storage Account to create.

.PARAMETER AutomationAccountName
The name of the Automation Account to create.

.PARAMETER VirtualNetworkName
The name of the Virtual Network to create.

.PARAMETER VMName
The name of the Hybrid Worker VM to create (max 15 characters).

.PARAMETER AdminUsername
The administrator username for the Hybrid Worker VM.

.PARAMETER AdminPassword
The administrator password for the Hybrid Worker VM as a SecureString.

.PARAMETER RunbookWorkerGroupName
The name of the Hybrid Worker group to create.

.PARAMETER TableName
The name of the Storage Table to create.

.PARAMETER vnetAddressPrefix
The address prefix for the Virtual Network (default: "10.0.0.0/16").

.PARAMETER PrivateEndpointSubnetAddressPrefix
The address prefix for the Private Endpoint subnet (default: "10.0.1.0/24").

.PARAMETER HybridWorkerSubnetAddressPrefix
The address prefix for the Hybrid Worker subnet (default: "10.0.2.0/24").

.PARAMETER Tags
Hashtable of tags to apply to all resources (default: Automation=HybridWorker, Department=DevOps).

.EXAMPLE
$params = @{
    ResourceGroupName = "MyResourceGroup"
    Location = "northcentralus"
    StorageAccountName = "mystorageacct545675"
    AutomationAccountName = "myautomation"
    VirtualNetworkName = "myvnet"
    VMName = "myvm"
    AdminUsername = "adminuser"
    AdminPassword = (ConvertTo-SecureString "Password123!" -AsPlainText -Force)
    RunbookWorkerGroupName = "MyWorkerGroup"
    TableName = "MyTable"
}
.\Set-PrivateLinkEnvironment.ps1 @params

.NOTES
File Name      : Set-PrivateLinkEnvironment.ps1
Author         : Bradley Wyatt
Prerequisite   : Azure PowerShell modules (Az.Network, Az.Storage, Az.Automation, Az.Compute, Az.OperationalInsights)
Version        : 1.0
Required Permissions : Subscription Contributor or equivalent custom role
Copyright 2024 : The Lazy Administrator

.LINK
https://learn.microsoft.com/en-us/azure/private-link/
https://learn.microsoft.com/en-us/azure/automation/automation-hybrid-runbook-worker
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory)]
    [string]$Location,
    
    [Parameter(Mandatory)]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory)]
    [string]$AutomationAccountName,
    
    [Parameter(Mandatory)]
    [string]$VirtualNetworkName,
    
    [Parameter(Mandatory)]
    [string]$VMName,
    
    [Parameter(Mandatory)]
    [string]$AdminUsername,
    
    [Parameter(Mandatory)]
    [SecureString]$AdminPassword,

    [Parameter(Mandatory)]
    [string]$RunbookWorkerGroupName,

    [Parameter(Mandatory)]
    [string]$TableName,

    [Parameter()]
    [string]$vnetAddressPrefix = "10.0.0.0/16",

    [Parameter()]
    [string]$PrivateEndpointSubnetAddressPrefix = "10.0.1.0/24",

    [Parameter()]
    [string]$HybridWorkerSubnetAddressPrefix = "10.0.2.0/24",

    [Parameter()]
    [hashtable]$Tags = @{
        "Automation" = "HybridWorker"
        "Department" = "DevOps"
    }
)
#Make sure $VMname does not exceed 15 characters
$VMName = $VMName.Substring(0, [Math]::Min(15, $VMName.Length))
# Subnet configurations
$subnetConfigs = @(
    @{
        Name                           = "PrivateEndpointSubnet"
        AddressPrefix                   = $PrivateEndpointSubnetAddressPrefix
        ServiceEndpoints               = @()
        PrivateEndpointNetworkPolicies = "Disabled"
    },
    @{
        Name                           = "HybridWorkerSubnet"
        AddressPrefix                   = $HybridWorkerSubnetAddressPrefix
        ServiceEndpoints               = @()
        PrivateEndpointNetworkPolicies = "Enabled"
    }
)
# Function to get public IP (kept for table management)
function Get-PublicIP {
    $publicIP = (Invoke-WebRequest -Uri "https://ipchicken.com" -UseBasicParsing).Content
    if ($publicIP -match '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b') { return $matches[0] }
    throw "Could not determine public IP address"
}

function Write-StepLog {
    param([string]$Message)
    if ($message -like "===*" -and $message -like "*End:*") {
        Write-Verbose "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
        Write-Verbose " "
    }
    else {
        Write-Verbose "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    }
}

function Write-ErrorAndExit {
    param([string]$Message)
    Write-Error "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    throw $Message
}

function Set-RequiredRoleAssignments {
    param(
        [string]$ObjectId,
        [string[]]$Roles,
        [string]$Scope,
        [bool]$IsServicePrincipal = $true
    )
    
    $missingRoles = Test-RequiredRoles -ObjectId $ObjectId -Roles $Roles -Scope $Scope -IsServicePrincipal $IsServicePrincipal
    
    if ($missingRoles.Count -eq 0) {
        Write-StepLog "All required roles are already assigned"
        return $false  # Indicates no changes were made
    }
    
    foreach ($role in $missingRoles) {
        try {
            $params = @{
                RoleDefinitionName = $role
                Scope              = $Scope
            }
            if ($IsServicePrincipal) {
                $params['ObjectId'] = $ObjectId
            }
            else {
                $params['SignInName'] = $ObjectId
            }
            New-AzRoleAssignment @params
            Write-StepLog "Successfully assigned role: $role"
        }
        catch {
            Write-StepLog "Error assigning role $role : $_"
        }
    }
    return $true  # Indicates changes were made
}

function Test-RequiredRoles {
    param(
        [string]$ObjectId,
        [string[]]$Roles,
        [string]$Scope,
        [bool]$IsServicePrincipal = $true
    )
    
    $missingRoles = @()
    foreach ($role in $Roles) {
        $params = @{
            RoleDefinitionName = $role
            Scope              = $Scope
            ErrorAction        = 'SilentlyContinue'
        }
        
        if ($IsServicePrincipal) {
            $params['ObjectId'] = $ObjectId
        }
        else {
            $params['SignInName'] = $ObjectId
        }
        
        $existing = Get-AzRoleAssignment @params
        if (-not $existing) {
            $missingRoles += $role
        }
    }
    return $missingRoles
}

try {
    Write-StepLog "=== Begin: Module Check ==="
    # Ensure required modules are installed
    $requiredModules = @('Az.Network', 'Az.Storage', 'Az.Automation', 'Az.Compute', 'Az.OperationalInsights')
    foreach ($module in $requiredModules) {
        Write-StepLog "Checking module: $module"
        if (!(Get-Module -ListAvailable -Name $module)) {
            Write-StepLog "Installing module: $module"
            Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
        }
    }
    Write-StepLog "=== End: Module Check ==="
    Connect-AzAccount -ErrorAction Stop
    # Get all subscriptions
    $subscriptions = Get-AzSubscription
    # If there's more than one subscription, let the user choose
    if ($subscriptions.Count -gt 1) {
        Write-Host "`nAvailable Subscriptions:" -ForegroundColor Cyan
    
        # Display subscriptions with numbers
        for ($i = 0; $i -lt $subscriptions.Count; $i++) {
            Write-Host ("{0}: {1} (ID: {2})" -f ($i + 1), $subscriptions[$i].Name, $subscriptions[$i].Id)
        }
    
        # Ask user to choose
        do {
            $selection = Read-Host "`nSelect subscription number (1-$($subscriptions.Count))"
            $selectionIndex = [int]$selection - 1
        } while ($selectionIndex -lt 0 -or $selectionIndex -ge $subscriptions.Count)
    
        # Set the selected subscription
        $selectedSubscription = $subscriptions[$selectionIndex]
        Set-AzContext -SubscriptionId $selectedSubscription.Id
    
        Write-Host "`nSelected subscription: $($selectedSubscription.Name)" -ForegroundColor Green
    }
    else {
        Write-Host "Using the only available subscription: $($subscriptions[0].Name)" -ForegroundColor Green
        Set-AzContext -SubscriptionId $subscriptions[0].Id
    }

    Write-StepLog "=== Begin: Resource Group Setup ==="
    #region: Resource Group
    # Create Resource Group if it doesn't exist
    if (!(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
        Write-StepLog "Resource Group $ResourceGroupName does not exist. Creating new group..."
        New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Tag $tags
    }
    else {
        Write-StepLog "Resource Group $ResourceGroupName already exists"
        # Get existing resource group and its tags
        $resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName
        $existingTags = $resourceGroup.Tags
        $needsUpdate = $false

        if ($existingTags) {
            # Check if any new tags are different from existing ones
            foreach ($key in $tags.Keys) {
                if (!$existingTags.ContainsKey($key) -or $existingTags[$key] -ne $tags[$key]) {
                    $needsUpdate = $true
                    break
                }
            }
        
            if ($needsUpdate) {
                $mergedTags = $existingTags.Clone()
                foreach ($key in $tags.Keys) {
                    $mergedTags[$key] = $tags[$key]
                }
                Write-StepLog "Updating resource group tags..."
                Set-AzResourceGroup -Name $ResourceGroupName -Tag $mergedTags
            }
            else {
                Write-StepLog "Resource group tags are already up to date"
            }
        }
        else {
            # No existing tags, set the new ones
            Write-StepLog "Adding tags to resource group..."
            Set-AzResourceGroup -Name $ResourceGroupName -Tag $tags
        }
    }
    #endregion
    Write-StepLog "=== End: Resource Group Setup ==="

    Write-StepLog "=== Begin: Starting Virtual Network Setup ==="
    #region: Virtual Network
    # Create new virtual network 
    Write-StepLog "Creating new Virtual Network: $VirtualNetworkName"
    $vnetParams = @{
        Name              = $VirtualNetworkName
        ResourceGroupName = $ResourceGroupName
        Location          = $Location
        AddressPrefix      = $vnetAddressPrefix
        Tag               = $tags
    }
    $vnet = New-AzVirtualNetwork @vnetParams

    # Create each subnet with the correct configuration
    foreach ($subnetConfig in $subnetConfigs) {
        Write-StepLog "Creating subnet: $($subnetConfig.Name)"

        # Create base subnet config first
        $subnetParams = @{
            Name          = $subnetConfig.Name
            AddressPrefix  = $subnetConfig.AddressPrefix
        }

        $subnet = New-AzVirtualNetworkSubnetConfig @subnetParams

        if ($subnetConfig.ServiceEndpoints -and $subnetConfig.ServiceEndpoints.Count -gt 0) {
            $subnetParams = @{
                Name            = $subnetConfig.Name
                AddressPrefix    = $subnetConfig.AddressPrefix
                ServiceEndpoint = $subnetConfig.ServiceEndpoints
            }

            $subnet = New-AzVirtualNetworkSubnetConfig @subnetParams
        }

        $vnet.Subnets.Add($subnet)
    }

    # Apply the configuration
    Write-StepLog "Applying Virtual Network configuration changes..."
    $vnet = Set-AzVirtualNetwork -VirtualNetwork $vnet
    #endregion
    Write-StepLog "=== End: Virtual Network Setup ==="

    #region: Storage Account
    Write-StepLog "=== Begin: Storage Account Configuration ==="
    try {
        Write-StepLog "Creating new Storage Account: $StorageAccountName"
        $storageAccountParams = @{
            ResourceGroupName       = $ResourceGroupName
            Name                    = $StorageAccountName
            Location                = $Location
            SkuName                 = 'Standard_LRS'
            Kind                    = 'StorageV2'
            EnableHttpsTrafficOnly   = $true
            MinimumTlsVersion       = 'TLS1_2'
            AllowBlobPublicAccess   = $false
            Tag                     = $tags
            NetworkRuleSet          = @{
                DefaultAction           = "Deny"
                VirtualNetworkRules     = @()
                IpRules                 = @()
            }
        }
        $storageAccount = New-AzStorageAccount @storageAccountParams

        Write-StepLog "Waiting for Storage Account provisioning..."
        $timeout = 300
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while (($timer.Elapsed.TotalSeconds -lt $timeout)) {
            $sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
            Write-StepLog "Current provisioning state: $($sa.ProvisioningState)"
            if ($sa.ProvisioningState -eq "Succeeded") {
                Write-StepLog "Storage Account provisioned successfully"
                break
            }
            Write-StepLog "Waiting 10 seconds before checking again..."
            Start-Sleep -Seconds 10
        }
        if ($timer.Elapsed.TotalSeconds -ge $timeout) {
            Write-ErrorAndExit "Timeout waiting for Storage Account provisioning"
        }

        # Verify network rules configuration
        Write-StepLog "Verifying network rules configuration..."
        $networkRules = $storageAccount.NetworkRuleSet

        if ($networkRules.DefaultAction -ne "Deny") {
            Write-StepLog "Updating network rules to deny public access by default..."
            $networkRuleParams = @{
                ResourceGroupName = $ResourceGroupName
                Name              = $StorageAccountName
                DefaultAction     = 'Deny'
            }

            Update-AzStorageAccountNetworkRuleSet @networkRuleParams
        }
    }
    catch {
        Write-ErrorAndExit "Error configuring storage account: $_"
    }
    #endregion
    Write-StepLog "=== End: Storage Account Configuration ==="

    # Automation Account Setup
    Write-StepLog "=== Begin: Automation Account Setup ==="
    # First check if Automation Account exists
    Write-StepLog "Checking if Automation Account already exists..."
    try {
        $existingAutomationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
    
        if ($existingAutomationAccount) {
            Write-StepLog "Automation Account exists, checking tags..."
            $existingTags = $existingAutomationAccount.Tags
            $needsUpdate = $false

            if ($existingTags) {
                # Check if any new tags are different from existing ones
                foreach ($key in $tags.Keys) {
                    if (!$existingTags.ContainsKey($key) -or $existingTags[$key] -ne $tags[$key]) {
                        $needsUpdate = $true
                        break
                    }
                }

                if ($needsUpdate) {
                    $mergedTags = $existingTags.Clone()
                    foreach ($key in $tags.Keys) {
                        $mergedTags[$key] = $tags[$key]
                    }
                    Write-StepLog "Updating automation account tags..."
                    $automationAccount = Set-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -Tag $mergedTags
                }
                else {
                    Write-StepLog "Automation account tags are already up to date"
                    $automationAccount = $existingAutomationAccount
                }
            }
            else {
                # No existing tags, set the new ones
                Write-StepLog "Adding tags to automation account..."
                $automationAccount = Set-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -Tag $tags
            }
        }
        else {
            # Create new automation account with tags
            $automationAccountParams = @{
                ResourceGroupName    = $ResourceGroupName
                Name                 = $AutomationAccountName
                Location             = $Location
                Plan                 = 'Basic'
                AssignSystemIdentity = $true
                Tag                  = $tags
                ErrorAction          = 'Stop'
            }

            $automationAccount = New-AzAutomationAccount @automationAccountParams
    
            Write-StepLog "Successfully created new Automation Account"
        }
    }
    catch {
        Write-ErrorAndExit "Failed to create Automation Account: $_"
    }
    Write-StepLog "=== End: Automation Account Setup ==="
    #endregion

    #region: Automation Account Managed Identity
    Write-StepLog "=== Begin: Automation Account Managed Identity ==="
    # Setup managed identity and role assignments
    Write-StepLog "Setting up managed identity and role assignments..."
    try {
        $retryCount = 0
        $maxRetries = 5
        $managedIdentityObjectId = $null
    
        while ($retryCount -lt $maxRetries -and -not $managedIdentityObjectId) {
            $retryCount++
            Write-StepLog "Attempt $retryCount to get managed identity..."
        
            $automationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName
            $managedIdentityObjectId = $automationAccount.Identity.PrincipalId
        
            if (-not $managedIdentityObjectId) {
                Write-StepLog "Managed identity not ready yet, waiting 30 seconds..."
                Start-Sleep -Seconds 30
            }
        }
    
        if (-not $managedIdentityObjectId) {
            Write-ErrorAndExit "Could not retrieve managed identity for Automation Account after $maxRetries attempts"
        }

        Write-StepLog "Automation Account managed identity Object ID: $managedIdentityObjectId"
        $roleParams = @{
            ObjectId           = $managedIdentityObjectId
            Roles              = @("Storage Table Data Contributor", "Storage Account Contributor")
            Scope              = $storageAccount.Id
            IsServicePrincipal = $true
        }

        $rolesChanged = Set-RequiredRoleAssignments @roleParams

        if ($rolesChanged) {
            Write-StepLog "Waiting for role assignments to propagate..."
            Start-Sleep -Seconds 120
        }
    }
    catch {
        Write-ErrorAndExit "Failed during managed identity setup: $_"
    }
    Write-StepLog "=== End: Automation Account Managed Identity ==="
    #endregion

    #region: Running Users Permissions
    Write-StepLog "=== Begin: Verifying Current User Permissions ==="
    # Get current user's context
    Write-StepLog "Getting current user context..."
    $currentUser = Get-AzContext
    Write-StepLog "Current user: $($currentUser.Account)"

    # Check current user's role assignments
    Write-StepLog "Checking current user's role assignments..."
    $userRoleAssignments = Get-AzRoleAssignment -Scope $storageAccount.Id | 
    Where-Object { $_.SignInName -eq $currentUser.Account.Id }

    Write-StepLog "Current user role assignments:"
    foreach ($role in $userRoleAssignments) {
        Write-StepLog "- $($role.RoleDefinitionName)"
    }

    # Required roles for the current user
    $currentUserRoleParams = @{
        ObjectId           = $currentUser.Account.Id
        Roles              = @("Storage Table Data Contributor", "Storage Account Contributor")
        Scope              = $storageAccount.Id
        IsServicePrincipal = $false
    }

    $rolesChanged = Set-RequiredRoleAssignments @currentUserRoleParams

    if ($rolesChanged) {
        Write-StepLog "Waiting for role assignments to propagate..."
        Start-Sleep -Seconds 120
    }
    Write-StepLog "=== End: Verifying Current User Permissions ==="
    #endregion

    #region: Storage Table
    Write-StepLog "=== Begin: Table and Permission Verification ==="
    # Check if table exists first
    $context = New-AzStorageContext -StorageAccountName $StorageAccountName
    Write-StepLog "Table does not exist. Starting creation process..."
    
    # Check current IP whitelist
    Write-StepLog "Checking current IP firewall rules..."
    $currentRules = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
    $myPublicIP = Get-PublicIP
        
    $ipExists = $currentRules.IpRules | Where-Object { $_.IPAddressOrRange -eq $myPublicIP }

    if (-not $ipExists) {
        Write-StepLog "Adding current IP to firewall rules..."
        $networkRuleParams = @{
            ResourceGroupName = $ResourceGroupName
            Name              = $StorageAccountName
            IPAddressOrRange  = $myPublicIP
        }

        Add-AzStorageAccountNetworkRule @networkRuleParams
            
        Write-StepLog "Waiting 30 seconds for firewall rule to apply..."
        Start-Sleep -Seconds 30
    }
    else {
        Write-StepLog "IP already exists in firewall rules, proceeding with table creation..."
    }

    # Check current user permissions
    Write-StepLog "Checking current user permissions..."
    $currentUser = Get-AzContext
    $userRoleParams = @{
        ObjectId           = $currentUser.Account.Id
        Roles              = @("Storage Account Contributor", "Storage Table Data Contributor")
        Scope              = $storageAccount.Id
        IsServicePrincipal = $false
    }

    $rolesChanged = Set-RequiredRoleAssignments @userRoleParams

    if ($rolesChanged) {
        Write-StepLog "Waiting for user role assignments to propagate..."
        Start-Sleep -Seconds 120
    }

    # Create the table
    Write-StepLog "Creating table '$tablename'..."
    New-AzStorageTable -Name "$tablename" -Context $context | Out-Null
    Write-StepLog "Table created successfully"
    Write-StepLog "=== End: Table and Permission Verification ==="
    #endregion


    #region: Private DNS Zone - Storage Table
    Write-StepLog "=== Begin: Private DNS Zone for Storage Table ==="
    Write-StepLog "Creating Private DNS Zone for Storage Table..."
    $dnsZoneName = "privatelink.table.core.windows.net"
    $tablePrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ResourceGroupName -Name $dnsZoneName -Tag $tags
    Write-StepLog "=== End: Private DNS Zone for Storage Table ==="
    #endregion  

    #Region: Private Dns Virtual Network Link - Storage Table
    Write-StepLog "=== Begin: Private DNS Virtual Network Link ==="
    Write-StepLog "Ensuring Virtual Network is properly retrieved..."
    $vnet = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName
    if (-not $vnet) {
        Write-ErrorAndExit "Virtual Network '$VirtualNetworkName' not found in resource group '$ResourceGroupName'"
    }

    Write-StepLog "Checking for existing DNS-VNet link..."
    $linkName = "tablevnetlink"
    Write-StepLog "Creating new DNS-VNet link..."
    $dnsLinkParams = @{
        ResourceGroupName = $ResourceGroupName
        Name              = $linkName
        ZoneName          = $tablePrivateDnsZone.Name
        VirtualNetworkId  = $vnet.Id
        Tag               = $tags
    }

    New-AzPrivateDnsVirtualNetworkLink @dnsLinkParams | Out-Null

    Write-StepLog "Verifying Storage DNS VNet Link..."
    $timeout = 300
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (($timer.Elapsed.TotalSeconds -lt $timeout)) {
        $dnsLinkParams = @{
            ResourceGroupName = $ResourceGroupName
            ZoneName          = $tablePrivateDnsZone.Name
            Name              = $linkName
        }

        $dnsLink = Get-AzPrivateDnsVirtualNetworkLink @dnsLinkParams
        if ($dnsLink.ProvisioningState -eq "Succeeded") {
            Write-StepLog "Storage DNS VNet Link provisioned successfully"
            break
        }
        Start-Sleep -Seconds 10
    }
    if ($timer.Elapsed.TotalSeconds -ge $timeout) {
        Write-Warning "Timeout waiting for Storage DNS VNet Link provisioning"
    }
    Write-StepLog "=== End: Private DNS Virtual Network Link ==="
    #endregion

    #region: Private Endpoint - Storage Table
    Write-StepLog "=== Begin: Private Endpoint for Storage Table ==="
    Write-StepLog "Creating Private Endpoint for Storage Account..."
    # Verify subnet configuration
    Write-StepLog "Verifying subnet configuration..."
    # Get the latest vnet configuration
    $vnet = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName
    $subnet = $vnet.Subnets | Where-Object { $_.Name -eq "PrivateEndpointSubnet" }

    if ($subnet.PrivateEndpointNetworkPolicies -ne "Disabled") {
        Write-StepLog "Updating subnet to disable private endpoint network policies..."
        $subnet.PrivateEndpointNetworkPolicies = "Disabled"
        $vnet | Set-AzVirtualNetwork
    }

    # Create the private link service connection
    Write-StepLog "Creating private link service connection..."
    $plsConnectionParams = @{
        Name                 = "storage-privatelink"
        PrivateLinkServiceId = $storageAccount.Id
        GroupId              = "table"
        RequestMessage       = "Please approve private endpoint connection for storage account"
    }

    $plsConnection = New-AzPrivateLinkServiceConnection @plsConnectionParams

    # Create the private endpoint
    Write-StepLog "Creating private endpoint..."
    try {
        $storagePrivateEndpointParams = @{
            ResourceGroupName            = $ResourceGroupName
            Name                         = "storage-privateendpoint"
            Location                     = $Location
            Subnet                       = $subnet
            PrivateLinkServiceConnection = $plsConnection
            Tag                          = $tags
            ErrorAction                  = 'Stop'
        }

        $storagePrivateEndpoint = New-AzPrivateEndpoint @storagePrivateEndpointParams
        
        Write-StepLog "Private endpoint created successfully"
    }
    catch {
        Write-StepLog "Error details: $_"
        Write-StepLog "Subnet ID: $($subnet.Id)"
        Write-StepLog "Storage Account ID: $($storageAccount.Id)"
        throw "Failed to create private endpoint. See error details above."
    }
    Write-StepLog "=== End: Private Endpoint for Storage Table ==="
    #endregion

    #region: Private DNS Zone Group - Storage Table
    Write-StepLog "=== Begin: Private DNS Zone Group for Storage Table ==="
    Write-StepLog "Creating DNS Zone Group for Storage Account..."
    $tableConfig = New-AzPrivateDnsZoneConfig -Name "privatelink.table.core.windows.net" -PrivateDnsZoneId $tablePrivateDnsZone.ResourceId
    $privateDnsZoneGroupParams = @{
        ResourceGroupName    = $ResourceGroupName
        PrivateEndpointName  = $storagePrivateEndpoint.Name
        Name                 = "storagednszonegroup"
        PrivateDnsZoneConfig  = $tableConfig
    }

    New-AzPrivateDnsZoneGroup @privateDnsZoneGroupParams

    Write-StepLog "Verifying Storage DNS Zone Group..."
    $timeout = 300
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (($timer.Elapsed.TotalSeconds -lt $timeout)) {
        $zoneGroupParams = @{
            ResourceGroupName   = $ResourceGroupName
            PrivateEndpointName = $storagePrivateEndpoint.Name
            Name                = "storagednszonegroup"
        }

        $zoneGroup = Get-AzPrivateDnsZoneGroup @zoneGroupParams
        if ($zoneGroup.ProvisioningState -eq "Succeeded") {
            Write-StepLog "Storage DNS Zone Group provisioned successfully"
            break
        }
        Start-Sleep -Seconds 10
    }
    if ($timer.Elapsed.TotalSeconds -ge $timeout) {
        Write-Warning "Timeout waiting for Storage DNS Zone Group provisioning"
    }
    Write-StepLog "=== End: Private DNS Zone Group for Storage Table ==="
    #endregion

    #region: Private DNS Zone - Automation Account
    Write-StepLog "=== Begin: Private DNS Zone for Automation Account ==="
    Write-StepLog "Creating Private DNS Zone for Automation Account..."
    $dnsZoneName = "privatelink.azure-automation.net"
    $automationPrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ResourceGroupName -Name $dnsZoneName -Tag $tags
    Write-StepLog "=== End: Private DNS Zone for Automation Account ==="
    #endregion

    #region: Private DNS Virtual Network Link - Automation Account
    Write-StepLog "=== Begin: Private DNS Virtual Network Link for Automation Account ==="
    Write-StepLog "Linking Automation Private DNS Zone to VNet..."
    $linkName = "automationvnetlink"
    Write-StepLog "Creating new DNS-VNet link..."
    $privateDnsVnetLinkParams = @{
        ResourceGroupName = $ResourceGroupName
        Name              = $linkName
        ZoneName          = $automationPrivateDnsZone.Name
        VirtualNetworkId  = $vnet.Id
        Tag               = $tags
    }

    New-AzPrivateDnsVirtualNetworkLink @privateDnsVnetLinkParams

    Write-StepLog "Verifying Automation DNS VNet Link..."
    $timeout = 300
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (($timer.Elapsed.TotalSeconds -lt $timeout)) {
        $dnsLinkParams = @{
            ResourceGroupName = $ResourceGroupName
            ZoneName          = $automationPrivateDnsZone.Name
            Name              = "automationvnetlink"
        }

        $dnsLink = Get-AzPrivateDnsVirtualNetworkLink @dnsLinkParams
        if ($dnsLink.ProvisioningState -eq "Succeeded") {
            Write-StepLog "Automation DNS VNet Link provisioned successfully"
            break
        }
        Start-Sleep -Seconds 10
    }
    if ($timer.Elapsed.TotalSeconds -ge $timeout) {
        Write-Warning "Timeout waiting for Automation DNS VNet Link provisioning"
    }
    Write-StepLog "=== End: Private DNS Virtual Network Link for Automation Account ==="
    #endregion

    #region: Private Endpoint - Automation Account
    Write-StepLog "=== Begin: Private Endpoint for Automation Account ==="
    # First, ensure we have the latest automation account object
    Write-StepLog "Retrieving current Automation Account details..."
    $automationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName
    if (-not $automationAccount) {
        Write-ErrorAndExit "Could not retrieve Automation Account details"
    }
    
    # Construct the resource ID for the automation account
    $automationResourceId = "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Automation/automationAccounts/{2}" -f `
        $automationAccount.SubscriptionId, `
        $ResourceGroupName, `
        $AutomationAccountName
    
    Write-StepLog "Constructed Automation Account Resource ID: $automationResourceId"
    
    # Get the subnet for the private endpoint
    Write-StepLog "Getting Private endpoint subnet configuration..."
    $subnet = Get-AzVirtualNetworkSubnetConfig -Name "PrivateEndpointSubnet" -VirtualNetwork $vnet
    if (-not $subnet) {
        Write-ErrorAndExit "Could not find PrivateEndPoint in Virtual Network"
    }

    # Create the private link service connection
    Write-StepLog "Creating private link service connection..."
    $plsConnectionName = "automation-privatelink"
    
    try {
        $plsConnectionParams = @{
            Name                 = $plsConnectionName
            PrivateLinkServiceId = $automationResourceId
            GroupId              = "DSCAndHybridWorker"
            ErrorAction          = 'Stop'
        }

        $automationPlsConnection = New-AzPrivateLinkServiceConnection @plsConnectionParams
            
        Write-StepLog "Creating private endpoint..."
        $privateEndpointName = "automation-privateendpoint"
        
        $privateEndpointParams = @{
            ResourceGroupName            = $ResourceGroupName
            Name                         = $privateEndpointName
            Location                     = $Location
            Subnet                       = $subnet
            PrivateLinkServiceConnection = $automationPlsConnection
            Tag                          = $tags
            ErrorAction                  = 'Stop'
        }

        $automationPrivateEndpoint = New-AzPrivateEndpoint @privateEndpointParams
            
        Write-StepLog "Private endpoint created successfully"
    }
    catch {
        Write-StepLog "Error creating private endpoint: $_"
    }
    Write-StepLog "=== End: Private Endpoint for Automation Account ==="
    #endregion

    #region: Private DNS Zone Group - Automation Account
    Write-StepLog "Creating DNS Zone Group for Automation Account..."
    $automationConfig = New-AzPrivateDnsZoneConfig -Name "privatelink.azure-automation.net" -PrivateDnsZoneId $automationPrivateDnsZone.ResourceId
    $privateDnsZoneGroupParams = @{
        ResourceGroupName    = $ResourceGroupName
        PrivateEndpointName  = $automationPrivateEndpoint.Name
        Name                 = "automationdnszonegroup"
        PrivateDnsZoneConfig = $automationConfig
    }

    New-AzPrivateDnsZoneGroup @privateDnsZoneGroupParams

    Write-StepLog "Verifying Automation DNS Zone Group..."
    $timeout = 300
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (($timer.Elapsed.TotalSeconds -lt $timeout)) {
        $zoneGroupParams = @{
            ResourceGroupName   = $ResourceGroupName
            PrivateEndpointName = $automationPrivateEndpoint.Name
            Name                = "automationdnszonegroup"
        }

        $zoneGroup = Get-AzPrivateDnsZoneGroup @zoneGroupParams
        if ($zoneGroup.ProvisioningState -eq "Succeeded") {
            Write-StepLog "Automation DNS Zone Group provisioned successfully"
            break
        }
        Start-Sleep -Seconds 10
    }
    if ($timer.Elapsed.TotalSeconds -ge $timeout) {
        Write-Warning "Timeout waiting for Automation DNS Zone Group provisioning"
    }
    Write-StepLog "=== End: Private DNS Zone Group for Automation Account ==="
    #endregion

    # Hybrid Worker VM Setup
    #region: Hybrid Worker VM
    Write-StepLog "=== Begin: Hybrid Worker VM Creation ==="
    $nsgName = "$VMName-nsg"
    $nsgParams = @{
        ResourceGroupName = $ResourceGroupName
        Location          = $Location
        Name              = $nsgName
        Tag               = $tags
    }

    $nsg = New-AzNetworkSecurityGroup @nsgParams

    Write-StepLog "Creating Hybrid Worker VM..."
    $vmConfig = New-AzVMConfig -VMName $VMName -VMSize "Standard_D2s_v3" -SecurityType "TrustedLaunch"

    # Set OS Configuration once
    $vm = Set-AzVMOperatingSystem -VM $vmConfig -Windows -ComputerName $VMName -Credential (New-Object PSCredential($AdminUsername, $AdminPassword)) -EnableAutoUpdate 

    # Set Security Profile
    $vm = Set-AzVMSecurityProfile -VM $vm -SecurityType "TrustedLaunch"
    $vm = Set-AzVMUefi -VM $vm -EnableVtpm $true -EnableSecureBoot $true

    # Set Source Image
    $vmSourceImageParams = @{
        VM            = $vm
        PublisherName = "MicrosoftWindowsServer"
        Offer         = "WindowsServer"
        Skus          = "2019-datacenter-gensecond"
        Version       = "latest"
    }

    $vm = Set-AzVMSourceImage @vmSourceImageParams

    Write-StepLog "Creating Public IP for VM..."
    $publicIPName = "$VMName-ip"
    $publicIpParams = @{
        Name              = $publicIPName
        ResourceGroupName = $ResourceGroupName
        Location          = $Location
        AllocationMethod  = 'Dynamic'
        Sku               = 'Basic'
        IpAddressVersion  = 'IPv4'
        Tag               = $tags
    }

    $publicIP = New-AzPublicIpAddress @publicIpParams

    Write-StepLog "Creating Network Interface for VM..."
    $nicParams = @{
        Name                   = "$VMName-nic"
        ResourceGroupName      = $ResourceGroupName
        Location               = $Location
        SubnetId               = (Get-AzVirtualNetworkSubnetConfig -Name "HybridWorkerSubnet" -VirtualNetwork $vnet).Id
        Tag                    = $tags
        NetworkSecurityGroupId = $nsg.Id
        PublicIpAddressId      = $publicIP.Id
    }

    $nic = New-AzNetworkInterface @nicParams

    $vm = Add-AzVMNetworkInterface -VM $vm -Id $nic.Id

    Write-StepLog "Deploying Hybrid Worker VM..."
    try {
        $tagsDictionary = [System.Collections.Generic.Dictionary[string, string]]::new()
        $tags.GetEnumerator() | ForEach-Object {
            $tagsDictionary.Add($_.Key, $_.Value)
        }
        # Add tags to the VM configuration
        $vm.Tags = $tagsDictionary

        $newVMParams = @{
            ResourceGroupName = $ResourceGroupName
            Location          = $Location
            VM                = $vm
            ErrorAction       = 'Stop'
        }

        New-AzVM @newVMParams

        Write-StepLog "VM deployment initiated successfully"
    }
    catch {
        Write-ErrorAndExit "Failed to deploy VM: $_"
    }

    # Wait for VM to be fully provisioned
    Write-StepLog "Waiting for VM to be fully provisioned..."
    $timeout = 600 # 10 minutes timeout
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $vmProvisioned = $false
    
    # Force a small delay to allow Azure to start the provisioning
    Start-Sleep -Seconds 30
    
    while (($timer.Elapsed.TotalSeconds -lt $timeout) -and (-not $vmProvisioned)) {
        try {
            $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName -ErrorAction SilentlyContinue
        
            if ($vm) {
                $vmStatus = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $vmName -Status -ErrorAction Stop
            
                if ($vmStatus) {
                    $provisioningState = ($vmStatus.Statuses | Where-Object { $_.Code -like "ProvisioningState/*" }).DisplayStatus
                    $powerState = ($vmStatus.Statuses | Where-Object { $_.Code -like "PowerState/*" }).DisplayStatus
                
                    Write-StepLog "Current VM status: $provisioningState, Power State: $powerState"
                
                    if ($provisioningState -eq "Provisioning succeeded" -and $powerState -eq "VM running") {
                        $vmProvisioned = $true
                        Write-StepLog "VM provisioning completed successfully"
                        break
                    }
                }
            }
        }
        catch {
            Write-StepLog "Error checking VM status: $_"
        }
        Start-Sleep -Seconds 30
    }

    Write-StepLog "Tagging the VM OS Disk..."
    $diskName = ((Get-AzVM -ResourceGroupName $resourceGroupName -Name $vmName).StorageProfile.OsDisk).name
    $disk = Get-AzDisk | Where-Object {$_.Name -eq $diskName}
    $diskResourceId = $disk.Id
    Update-AzTag -ResourceId $diskResourceId -Tag $tags -Operation Merge
    Update-AzTag -ResourceId $diskResourceId -Tag @{"vmName" = $vmName } -Operation Merge
    Update-AzTag -ResourceId $diskResourceId -Tag @{"Purpose" = "OS Disk" } -Operation Merge

    #Get VM Information
    Write-StepLog "Tagging the VM Boot Diagnostics Disk..."
    $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
    # Get the diagnostics storage account
    $storageURL = $vm.DiagnosticsProfile.BootDiagnostics.StorageUri
    # $storageURL will be formatted like https://theldevtesvmh121612220.blob.core.windows.net/, we need to extract the disk name
    $storageAccountName = $storageURL.Split('/')[2].Split('.')[0]
    $diskInfo = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $storageAccountName 
    Update-AzTag -ResourceId $diskInfo.Id -Tag @{"vmName" = $vmName } -Operation Merge
    Update-AzTag -ResourceId $diskInfo.Id -Tag @{"Purpose" = "Boot Diagnostics" } -Operation Merge
    Update-AzTag -ResourceId $diskInfo.Id -Tag $tags -Operation Merge


    Write-StepLog "=== End: Hybrid Worker VM Creation ==="
    #endregion

    #region: Hybrid Worker Managed Identity
    Write-StepLog "=== Begin: Hybrid Worker Managed Identity ==="
    # Enable system-assigned managed identity
    Write-StepLog "Enabling system-assigned managed identity on VM..."
    try {
        Update-AzVM -ResourceGroupName $ResourceGroupName -VM $vm -IdentityType SystemAssigned
        Start-Sleep -Seconds 30

        # Get the updated VM with identity
        Write-StepLog "Getting updated VM with managed identity..."
        $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
        $managedIdentityObjectId = $vm.Identity.PrincipalId

        Write-StepLog "Assigning RBAC roles to VM's managed identity..."

        $rolesChangedParams = @{
            ObjectId           = $managedIdentityObjectId
            Roles              = @("Contributor")
            Scope              = "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName"
            IsServicePrincipal = $true
        }

        $rolesChanged = Set-RequiredRoleAssignments @rolesChangedParams

        if ($rolesChanged) {
            Write-StepLog "Waiting for role assignments to propagate..."
            Start-Sleep -Seconds 60
        }
    }
    catch {
        Write-ErrorAndExit "Failed to configure managed identity: $_"
    }
    Write-StepLog "=== End: Hybrid Worker Managed Identity ==="
    #endregion

    #region: Hybrid Worker Setup
    try {
        Write-StepLog "=== Begin: Hybrid Worker Setup ==="
        # Get the VM details
        $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
        Write-StepLog "Creating Hybrid Worker Group..."
        New-AzAutomationHybridRunbookWorkerGroup -AutomationAccountName $AutomationAccountName -Name $RunbookWorkerGroupName -ResourceGroupName $ResourceGroupName
        $guid = new-guid
        Write-StepLog "Creating Hybrid Worker..."
        $workerParams = @{
            AutomationAccountName        = $AutomationAccountName
            Name                         = $guid
            HybridRunbookWorkerGroupName = $RunbookWorkerGroupName
            VmResourceId                 = $vm.Id
            ResourceGroupName            = $ResourceGroupName
        }

        New-AzAutomationHybridRunbookWorker @workerParams        #Install Hybrid Worker Extension on the VM.

        # Check the extension status
        # Do a GET request to get the automationHybridServiceUrl property 
        Write-StepLog "Getting the current subscription id..."
        $subscriptionId = (Get-AzContext).Subscription.Id
        $token = (Get-AzAccessToken).Token
        $headers = @{
            'Authorization' = "Bearer $token"
            'Content-Type'  = 'application/json'
        }
        Write-StepLog "Getting the Automation Account hybrid service url from the API..."
        $AutomationAcountUri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Automation/automationAccounts/$automationAccountName`?api-version=2023-11-01"
        $AutomationDetails = Invoke-RestMethod -Uri $AutomationAcountUri -Method Get -Headers $headers 

        $settings = @{
            "AutomationAccountURL" = "$($automationdetails.properties.automationhybridserviceurl)";
        };
        Write-StepLog "Installing Hybrid Worker Extension on VM..."
        $extensionParams = @{
            ResourceGroupName     = $ResourceGroupName
            Location              = $Location
            VMName                = $VMName
            Name                  = "HybridWorkerExtension"
            Publisher             = "Microsoft.Azure.Automation.HybridWorker"
            ExtensionType         = "HybridWorkerForWindows"
            TypeHandlerVersion    = "1.1"
            Settings              = $settings
            EnableAutomaticUpgrade = $true
        }

        Set-AzVMExtension @extensionParams    
    }
    catch {
        Write-ErrorAndExit "Failed to Hybrid Worker Setup: $_"
    }
    Write-StepLog "=== End: Worker Setup Complete ==="
    #endregion

    #region: Install PowerShell 7 on Hybrid Worker VM
    Write-StepLog "=== Begin: Installing PowerShell 7 on Hybrid Worker VM ==="
    Try {
        $ScriptBlock = {
            Invoke-WebRequest "https://github.com/PowerShell/PowerShell/releases/download/v7.2.24/PowerShell-7.2.24-win-x64.zip" -outfile "./pwsh7.zip"
            expand-archive "./pwsh7.zip" -destination C:\PowerShell7 -force
        }
            
        $vmCommandParams = @{
            ResourceGroupName = $ResourceGroupName
            VMName            = $VMName
            CommandId         = 'RunPowerShellScript'
            ScriptString      = $ScriptBlock
        }

        Invoke-AzVMRunCommand @vmCommandParams    
    }
    catch {
        Write-ErrorAndExit "Failed to install PowerShell 7 on Hybrid Worker VM: $_"
    }
    Write-StepLog "=== End: Installing PowerShell 7 on Hybrid Worker VM ==="
    #endregion

    #region: install nuget provider
    Write-StepLog "=== Begin: Installing Nuget Provider ==="
    # install nuget provider
    $ScriptBlock = {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
    }
    Write-StepLog "Installing NuGet provider..."
    $vmCommandParams = @{
        ResourceGroupName = $ResourceGroupName
        VMName            = $VMName
        CommandId         = 'RunPowerShellScript'
        ScriptString      = $ScriptBlock
    }

    Invoke-AzVMRunCommand @vmCommandParams

    Write-StepLog "=== End: Installing Nuget Provider ==="
    #endregion

    #region: Set PSGallery as trusted
    # Set PSGallery as trusted
    Write-StepLog "=== Begin: Installing PowerShell 7 on Hybrid Worker VM ==="
    try {
        Write-StepLog "Setting PSGallery as trusted..."
        $ScriptBlock = {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
        }
        $vmCommandParams = @{
            ResourceGroupName = $ResourceGroupName
            VMName            = $VMName
            CommandId         = 'RunPowerShellScript'
            ScriptString      = $ScriptBlock
        }

        Invoke-AzVMRunCommand @vmCommandParams
    }
    catch {
        Write-ErrorAndExit "Failed to set PSGallery as trusted: $_"
    }
    Write-StepLog "=== End: Setting PSGallery as trusted ==="
    #endregion
    Write-StepLog "Script completed successfully!"
}
catch {
    Write-ErrorAndExit $_.Exception.Message
}
