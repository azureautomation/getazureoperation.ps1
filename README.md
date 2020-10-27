Get-AzureOperation.ps1
======================

            

Returns an XML file with the subscription operation history from the specific number of days.


By specifying the -restart parameter and specifying a service name, VM name, username and password, it will connect to the specific Azure VM, return the 1074 events from the System log, and combine that in a timeline with the restart-related operations for
 that Azure VM. That timeline is output to CSV file by default.



        
    
TechNet gallery is retiring! This script was migrated from TechNet script center to GitHub by Microsoft Azure Automation product group. All the Script Center fields like Rating, RatingCount and DownloadCount have been carried over to Github as-is for the migrated scripts only. Note : The Script Center fields will not be applicable for the new repositories created in Github & hence those fields will not show up for new Github repositories.
