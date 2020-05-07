Get-UDDashboard | Stop-UDDashboard


Import-Module (Join-Path $PSScriptRoot 'HomeComputerFunctions.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RemoteComputerFunctions.psm1') -Force

$HomePageContent = {
    New-UDCard  -Content {
        New-UDHeading -Text "Network Scan" -Size 5

        New-UDHeading -Size 6 -Content { "Retrieve the list of available computers on this network, using one of the 2 options" } 
        
        # New-UDTabContainer starts
        New-UDTabContainer -Tabs {
            # New-UDTab starts
            New-UDTab -Text "Upload a CSV containing IPs and Passwords" -Content {
                New-UDInput -Title "Browse" -SubmitText "Upload" -BackgroundColor "white" -Id "networkscan" -Content {
                    New-UDInputField -Type binaryFile -Name file 
                     } -Endpoint {
                    param($File)
                    Show-UDToast -Message "Dummy"
                }            
            }
            # New-UDTab ends
            
            # New-UDTab starts
            New-UDTab -Text "Scan the Network" -Content {
                New-UDRow -Endpoint {
                    New-UDColumn -Endpoint {
                        New-UDButton -Text "Scan Network" -OnClick {
                            Show-UDToast -Message "Retrieving Network Details"
                            RetrieveNetwork
                            Show-UDToast -Message "Refresh the Page"
                        }
                    }
                }
            }
            # New-UDTab ends
        }
        # New-UDTabContainer ends

    }
    
    New-UDCard -Content {
        New-UDHeading -Text "List of Available Computers" -Size 5
        # New-UDPreloader -ProgressColor green
        New-UDRow -Endpoint {
            if($Cache:network -eq $null)
            {
                New-UDPreloader -ProgressColor green

                RetrieveNetwork
                DisplayNetworkEndpoints
            }else{
                Show-UDToast -Message "Loading directly from cache"
                DisplayNetworkEndpoints
            }
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
        
        
        #New-UDRow -Endpoint { New-CheckCard } 

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
                Get_Processes
            } 
        }
        New-UDRow -Endpoint {
            New-UDColumn -Size 6 -Content {
                CPU_Monitor
            } 
            New-UDColumn -Size 6 -Content {
                Memory_Monitor
            } 
        }
        New-UDRow -Endpoint {
            New-UDColumn -Size 6 -Content {
                Disk_Monitor
            } 
            New-UDColumn -Size 6 -Content {
                Network_Monitor
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
                    } 
                )
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

    New-UDRow -Endpoint {   New-InstallSoftwareCardAway  } 

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
    #         Get_ProcessesAway
    #     } 
    # }
    # New-UDRow -Endpoint {
    #     New-UDColumn -Size 6 -Content {
    #         CPU_MonitorAway
    #     } 
    #     New-UDColumn -Size 6 -Content {
    #         Memory_MonitorAway
    #     } 
    # }
    # New-UDRow -Endpoint {
    #     New-UDColumn -Size 6 -Content {
    #         Disk_MonitorAway
    #     } 
    #     New-UDColumn -Size 6 -Content {
    #         Network_MonitorAway
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

# $Pages = @()

# foreach ($endpoint in $Cache:network) {
#     $Page = 
# }

$LoginPage = New-UDLoginPage -AuthenticationMethod $AuthenticationMethod -PageBackgroundColor "#3f51b5"
$HomePage = New-UDPage -Name "Home" -Icon home -Content $HomePageContent
$Page1 = New-UDPage -Name "192.168.0.151" -Icon "laptop" -Content $Contenthome 
$Page2 = New-UDPage -Name "192.168.0.150" -Icon "laptop" -Endpoint $Contentaway
$Page3 = New-UDPage  -Url "/Office365/Client/:clientguid" -Title "Office365Clients" -Icon "cloud" -Endpoint {
    param(
        [Parameter(
            Mandatory = $true
        )]
        $clientguid
    )
    New-UDRow -Columns {
        New-UDColumn -MediumSize 2 -Id "Return" -Content {
            New-UDButton -Text "Return to overview $($clientguid)" -Flat -OnClick {
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
#Start-UDDashboard -Port 7777 -Dashboard $Dashboard -Wait