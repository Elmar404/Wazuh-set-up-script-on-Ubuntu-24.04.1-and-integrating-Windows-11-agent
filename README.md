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

*nano setup_wazuh_4.7.sh

Make the script executable:
*chmod +x setup_wazuh_4.7.sh

Run the script:
sudo bash ./wazuh-install.sh --ignore-check -a
--------------------------------------------------------------------------------------------------
