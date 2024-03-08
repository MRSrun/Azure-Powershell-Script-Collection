Connect-AzAccount
$data = @()
$Subscriptions = Get-AzSubscription
ForEach ($Subscription in $Subscriptions) {
    $SubscriptionID = $Subscription.Id
    Set-AzContext -Subscription $SubscriptionID
    $RGs = Get-AzResourceGroup
    foreach ($RG in $RGs) {
        $VMs = Get-AzVM -ResourceGroupName $RG.ResourceGroupName
        foreach ($VM in $VMs) {
            $NC = Get-AzVMSize -ResourceGroupName $RG.ResourceGroupName -VMName $VM.Name | Where-Object { $_.Name -eq $VM.HardwareProfile.VmSize } | Select-Object { $_.NumberOfCores }
            $data += New-Object psobject -Property @{
            "SubscriptionName" = $Subscription.Name
            "VMName" = $VM.Name
            "OSType" = $VM.StorageProfile.OSDisk.OSType
            "OSVersion" = $Vm.StorageProfile.ImageReference.Sku
            "ResourceGroup" = $RG.ResourceGroupName
            "Location" = $VM.Location
            "LicenseType" = $VM.LicenseType
            "CPUCores" = $NC.' $_.NumberOfCores '
            }

        }
    }
}

$data | Export-Csv C:\temp\report.csv

Disconnect-AzAccount