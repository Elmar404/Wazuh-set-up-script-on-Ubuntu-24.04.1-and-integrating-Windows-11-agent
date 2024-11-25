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
- sudo bash ./wazuh-install.sh --ignore-check --overwrite -a
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
 ------------------------------------------------
 VirusTotal integrate
Edit the Wazuh Manager configuration file:

sudo nano /var/ossec/etc/ossec.conf

Add the following integration block within the <ossec_config> tags, replacing <YOUR_VIRUS_TOTAL_API_KEY> with your actual API key:

<integration>
  <name>virustotal</name>
  <api_key>7ff6b1d4987978e40674f301499e10a2ae942d96b6fac9aa830596d2a9fde56b</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>

Configure File Integrity Monitoring (FIM):

    Define the directories you want to monitor. For example, to monitor the /root directory in real-time:

<syscheck>
  <directories realtime="yes">/root</directories>
</syscheck>

Create an active response script that removes files detected as malicious by VirusTotal.

sudo nano /var/ossec/active-response/bin/remove-threat.sh --- copy script is here

Make the script executable and set appropriate permissions:

sudo chmod 750 /var/ossec/active-response/bin/remove-threat.sh
sudo chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh

Install jq to process JSON input:

sudo apt update
sudo apt -y install jq

Configure Active Response in Wazuh:

Edit the ossec.conf file to define the active response command and associate it with the appropriate rules:
 <command>
  <name>remove-threat</name>
  <executable>remove-threat.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>remove-threat</command>
  <location>local</location>
  <rules_id>87105</rules_id>
</active-response>

This configuration sets up the active response to execute the remove-threat.sh script when a file is detected as malicious.

Define Custom Rules for Active Response:

Create a custom rules file:

sudo nano /var/ossec/etc/rules/local_rules.xml

 <group name="virustotal,">
  <rule id="100092" level="12">   
<if_sid>657</if_sid>
<match>Successfully removed threat</match>
<description>$(parameters.program) removed threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>
  <rule id="100093" level="12">
<if_sid>657</if_sid>
<match>Error removing threat</match>
<description>Error removing threat located at $(parameters.alert.data.virustotal.source.file)</description
  </rule>
</group>

Restart Wazuh Manager to Apply Changes:

sudo systemctl restart wazuh-manager

