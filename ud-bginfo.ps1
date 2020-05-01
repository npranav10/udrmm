Get-UDDashboard | Stop-UDDashboard

Import-Module (Join-Path $PSScriptRoot 'HomeComputerFunctions.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RemoteComputerFunctions.psm1') -Force

$HomePageContent = {
    New-UDRow -Endpoint {
        New-UDColumn -Size 3 -Content {
            New-UDCard -Title "192.168.0.102" -Text "Host Computer" -BackgroundColor "#a6ffc2" -Links @(
                New-UDLink -Url http://localhost:7777/192.168.0.102 -Text "Go to the Endpoint's Homepage"
                )
        }
        New-UDColumn -Size 3 -Content {
        New-UDCard -Title "192.168.0.150" -Text "Remote Computer" -BackgroundColor "#ffa6a6" 
                New-UDButton -Text "Wake-on-LAN" -OnClick (
                    New-UDEndpoint -Endpoint {
                        Wake-on-LAN 
                                            } )
        }
        New-UDColumn -Size 3 -Content {
            New-UDCard -Title "192.168.0.150" -Text "Remote Computer" -BackgroundColor "#a6ffc2" -Links @(
                New-UDLink -Url http://localhost:7777/192.168.0.150 -Text "Go to the Endpoint's Homepage"
                )
            }
    }
}

$Contenthome =  {
        New-UDRow -Endpoint {    New-InstallSoftwareCard    } 
        
        New-UDRow -Endpoint {
            New-UninstallSoftwareCard
            } -AutoRefresh -RefreshInterval 60

        New-UDRow -Endpoint {
            New-ListSoftwareCard
            } -AutoRefresh -RefreshInterval 5

        New-UDRow -Endpoint {
        New-UDColumn -Size 6 -Content {
            New-OverviewCard 
        }
        New-UDColumn -Size 6 -Content {
            New-NetworkCard
        } 
        } -AutoRefresh -RefreshInterval 60

        New-UDRow -Endpoint {
            New-UDColumn -Size 6 -Content {
                New-StorageCard
            } 
            New-UDColumn -Size 6 -Content {
                New-Resource
            } 
        } -AutoRefresh -RefreshInterval 1
        New-UDRow -Endpoint {
            New-UDColumn -Size 12 -Content {
                Get-Processes
            } 
        }
        New-UDRow -Endpoint {
            New-UDColumn -Size 6 -Content {
                CPU-Monitor
            } 
            New-UDColumn -Size 6 -Content {
                Memory-Monitor
            } 
        }
        New-UDRow -Endpoint {
            New-UDColumn -Size 6 -Content {
                Disk-Monitor
            } 
            New-UDColumn -Size 6 -Content {
                Network-Monitor
            } 
        }
}

$Contentaway =  {
    New-UDRow -Endpoint {
            New-UDColumn -Size 2 -Content {
                New-UDButton -Text "Remote Desktop" -OnClick (
                    New-UDEndpoint -Endpoint {
                        Show-UDToast -Message "Initiaing Remote Desktop connection !"
                        RemoteDesktop 
                                            } )
            }
            New-UDColumn -Size 2 -Content {
                New-UDButton -Text "Lock Computer" -OnClick (
                    New-UDEndpoint -Endpoint {
                        Show-UDToast -Message "Initiaing RemoteLock !"
                        RemoteLock 
                                            } )
                        }
            New-UDColumn -Size 2 -Content {
                New-UDButton -Text "Restart Computer" -OnClick (
                    New-UDEndpoint -Endpoint {
                        Show-UDToast -Message "Initiaing Remote Desktop connection !"
                        RemoteRestart 
                                            } )
                                    }
            New-UDColumn -Size 2 -Content {
                New-UDButton -Text "Shutdown Computer" -OnClick (
                    New-UDEndpoint -Endpoint {
                        Show-UDToast -Message "Initiaing Remote Desktop connection !"
                        RemoteShutdown 
                                            } )     
                                        }                        
    }

    New-UDRow -Endpoint {   New-InstallSoftwareCardAway    } 

    New-UDRow -Endpoint {
        New-UninstallSoftwareCardAway
        } 

    New-UDRow -Endpoint {
        New-ListSoftwareCardAway
        } -AutoRefresh -RefreshInterval 5

    New-UDRow -Endpoint {
    New-UDColumn -Size 6 -Content {
       New-OverviewCardAway 
    }
    New-UDColumn -Size 6 -Content {
        New-NetworkCardAway
    } 
    } -AutoRefresh -RefreshInterval 60

    New-UDRow -Endpoint {
        New-UDColumn -Size 6 -Content {
            New-StorageCardAway
        } 
        New-UDColumn -Size 6 -Content {
            New-ResourceAway
        } 
    } -AutoRefresh -RefreshInterval 1
    # New-UDRow -Endpoint {
    #     New-UDColumn -Size 12 -Content {
    #         Get-ProcessesAway
    #     } 
    # }
    # New-UDRow -Endpoint {
    #     New-UDColumn -Size 6 -Content {
    #         CPU-MonitorAway
    #     } 
    #     New-UDColumn -Size 6 -Content {
    #         Memory-MonitorAway
    #     } 
    # }
    # New-UDRow -Endpoint {
    #     New-UDColumn -Size 6 -Content {
    #         Disk-MonitorAway
    #     } 
    #     New-UDColumn -Size 6 -Content {
    #         Network-MonitorAway
    #     } 
    # }
}

$AuthenticationMethod = New-UDAuthenticationMethod -Endpoint {
    param([PSCredential]$Credentials)

    if ($Credentials.UserName -eq "sachin" -and $Credentials.GetNetworkCredential().Password -eq "vitcc") {
        New-UDAuthenticationResult -Success -UserName "sachin"
    }

    New-UDAuthenticationResult -ErrorMessage "You are not Sachin Tendulkar !"
}


$LoginPage = New-UDLoginPage -AuthenticationMethod $AuthenticationMethod -PageBackgroundColor "#3f51b5"
$HomePage = New-UDPage -Name "Home" -Icon home -Content $HomePageContent
$Page1 = New-UDPage -Name "192.168.0.102" -Icon "laptop" -Content $Contenthome 
$Page2 = New-UDPage -Name "192.168.0.150" -Icon "laptop" -Content $Contentaway
$Page3 = New-UDPage  -Url "/Office365/Client/:clientguid" -Title "Office365Clients" -Icon "cloud" -Endpoint {
    param(
        [Parameter(
            Mandatory = $true
        )]
        $clientguid
    )
    New-UDRow -Columns {
        New-UDColumn -MediumSize 2 -Id "Return" -Content {
            New-UDButton -Text "Return to overview" -Flat -OnClick {
                Invoke-UDRedirect -Url "http://localhost:7777/Home"
            }
        }

        }
}
    
$EndpointInitialization = New-UDEndpointInitialization -Module @("$PSScriptRoot\HomeComputerFunctions.psm1", "$PSScriptRoot\RemoteComputerFunctions.psm1")
#$EndpointInitialization = New-UDEndpointInitialization -Module @("$PSScriptRoot\HomeComputerFunctions.psm1")
# $HomePage = New-UDPage -Name "Home" -Icon home -Content $HomePageContent
# $null = $Pages.Insert(0,$HomePage)
# $Page1 = New-UDPage -Name "aaaa" -Endpoint $FilesPageContent
# $Page2 = New-UDPage -Name "Links" -Icon link -Content { New-UDCard }    
 $Dashboard  = New-UDDashboard -Title "Apache Heimdall - Endpoint Configuration Tool by @npranav10" -Pages @($HomePage,$Page1, $Page2,$Page3) -EndpointInitialization $EndpointInitialization #-LoginPage $LoginPage 

# $Dashboard = New-UDDashboard -Title "$env:ComputerName - Endpoint Configuration Tool by @npranav10" -Content $Content  -EndpointInitialization $EndpointInitialization 

Start-UDDashboard -Port 7777 -Dashboard $Dashboard -AdminMode -AutoReload -AllowHttpForLogin