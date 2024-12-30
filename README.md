# Overview
A common and recommended security practice is only allowing access to an Azure Storage Account via a whitelisted IP address. While this is generally a good idea, a problem arises when you need an Azure Automation Account to access one of these Storage Accounts. Currently, even if you whitelist an entire Azure region, your automation runbook will fail to connect to your Storage Account. Instead, you must use an Azure Private Link to connect Azure Automation to your PaaS Azure Resources securely, but “in the current implementation of Private Link, Automation account cloud jobs cannot access Azure resources that are secured using private endpoint. For example, Azure Key Vault, Azure SQL, Azure Storage account, etc. To workaround this, use a [Hybrid Runbook Worker](https://learn.microsoft.com/en-us/azure/automation/automation-hybrid-runbook-worker) instead. Hence, on-premises VMs are supported to run Hybrid Runbook Workers against an Automation Account with Private Link enabled.” [^1]

This configuration isn’t as simple as creating or deploying a traditional Azure Runbook; you must create private endpoints, subnets, DNS zones, hybrid worker groups, and more. I wanted to make a PowerShell script that anyone could run, and it would generate everything for you from start to finish, so in the end, it would be working out of the box without additional configuration needed. This includes installing PowerShell Core on the Hybrid Runbook Worker. The diagram below gives an architectural overview of the deployment and configuration.

> [!NOTE] Note
> Private Link support with Azure Automation is available only in Azure Commercial and Azure US Government clouds.
>
> 
