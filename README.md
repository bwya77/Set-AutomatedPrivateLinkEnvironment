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

## Pre-requisites
1. Az Module
	1. Az.Network
	2. Az.Storage
	3. Az.Automation
	4. Az.Compute
	5. Az.OperationalInsights
2. Azure Subscription
3. Proper Azure Permissions to create and manage resources within a subscription

> [!NOTE] 
> While the script deploys the hybrid worker VM with a public IP address, you can remove the public IP address from the hybrid worker upon completion. I added it so I could install `Pwsh7` and set up Bastion access.
