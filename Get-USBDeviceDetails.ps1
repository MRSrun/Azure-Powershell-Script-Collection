function Get-USBDeviceDetails {
    # Using WMI to query USB devices
    $usbDevices = Get-CimInstance -ClassName Win32_PnPEntity | Where-Object {
        $_.PNPClass -eq 'USB' -or $_.DeviceID -like '*USBSTOR*'
    }

    $deviceDetails = @()

    foreach ($device in $usbDevices) {
        # Parse DeviceID for VID, PID, and Serial Number
        if ($device.DeviceID -match 'VID_([0-9A-F]{4})&PID_([0-9A-F]{4}).*?\\([^\\]+)$') {
            $vid = $matches[1]
            $pid1 = $matches[2]
            $serialNumber = $matches[3]
        } else {
            $vid = $null
            $pid1 = $null
            $serialNumber = $null
        }

        # Add details to the result
        $deviceDetails += [PSCustomObject]@{
            DeviceID       = $device.DeviceID
            FriendlyNameID = $device.Name
            HardwareID     = $device.HardwareID -join '; '
            InstancePathID = $device.PNPDeviceID
            PID            = $pid1
            PrimaryID      = $device.PNPClass
            SerialNumberID = $serialNumber
            VID            = $vid
            VID_PID        = if ($vid -and $pid1) { "$vid"+"_"+"$pid1" } else { $null }
        }
    }

    return $deviceDetails
}

# Get USB Device Details and Output to Console
$usbDeviceDetails = Get-USBDeviceDetails

# Display in a formatted table
$usbDeviceDetails | Out-GridView
