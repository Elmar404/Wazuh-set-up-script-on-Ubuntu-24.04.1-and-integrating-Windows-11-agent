# Wazuh-set-up-script-on-Ubuntu-24.04.1-and-integrating-Windows-11-agent

Script Explanation

    Download Wazuh Install Script:
        The wget command downloads the official Wazuh wazuh-install.sh script for version 4.7.
        The -a flag in the script automates the installation, setting up all required components (Wazuh Manager, Filebeat, OpenSearch, and Wazuh Dashboard).

    System Update:
        The script updates the system and installs required dependencies.

    Execute the Script:
        The downloaded script (wazuh-install.sh) is executed with bash and proper permissions.

    Post-Installation:
        Restarts the Wazuh services to ensure they are running correctly.

        
Copy the script to a file, e.g., setup_wazuh_4.7.sh:
- nano setup_wazuh_4.7.sh

Make the script executable:
- chmod +x setup_wazuh_4.7.sh

Run the script:
- sudo bash ./wazuh-install.sh --ignore-check -a
--------------------------------------------------------------------------------------------------
Windows 11 agent
Powershell
Run the script:
.\install_wazuh_agent.ps1 
![image](https://github.com/user-attachments/assets/ae5417fb-d502-47eb-93b6-0c7834b2cc3b)
You can encounter such a error. Dont worry!

 First check wazuh-agent   -- Get-Service -Name "wazuh-agent"
 
 If it is not running --  Restart-Service -Name "wazuh-agent"
 
 Also check -- Test-NetConnection -ComputerName <your server ip> -Port 1514
 
 If the service doesn’t exist, manually register it:
 
 cmd 
 
 -- sc create "wazuh-agent" binPath= "C:\Program Files (x86)\ossec-agent\wazuh-agent.exe"
 
 net start "wazuh-agent"
 
 Run the following command to confirm the status of the wazuh-agent service:
 
 cmd
 
 sc query "wazuh-agent"
 
 Also you can write 
 
 cmd
 
 -- msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /quiet WAZUH_MANAGER=192.168.1.136 WAZUH_AGENT_NAME=DESKTOP-8T86KBH WAZUH_REGISTRATION_SERVER=192.168.1.136
 
 Do your own search!
 

 

