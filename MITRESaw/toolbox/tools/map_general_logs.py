#!/usr/bin/env python3 -tt
import re


def generic_mapping(
    technique_id,
    platforms,
    dataset,
    evidence_type,
):
    # converting log sources to generic but specific identifiers
    # the reason for including both is that this includes the manual scrapping of ATT&CK data sources whereas the data in 'evidence' is automatically extracted from both the technique description and group procedures and there may be instances whereby data is missing from one
    logsource = (  # need to also include specific executables/files such as lsass.exe and svchost.exe etc. which relate to specific techniques
        dataset.replace(
            "Active Directory: Active Directory Credential Request",
            "SecurityAD EventLog: 4624;4634;4663;4672;4679;4768;4769",
        )
        .replace(
            "Active Directory: Active Directory Object Access",
            "SecurityAD EventLog: 4661;4662",
        )
        .replace(
            "Active Directory: Active Directory Object Creation",
            "SecurityAD EventLog: 5137",
        )
        .replace(
            "Active Directory: Active Directory Object Deletion",
            "SecurityAD EventLog: 5141",
        )
        .replace(
            "Active Directory: Active Directory Object Modification",
            "SecurityAD EventLog: 4899;4900;4928;4929;5136;5163",
        )
        .replace(
            "Application Log: Application Log Content",
            "Application specific logging; DHCP EventLog: 1020;1063;1341;1342",
        )
        .replace(
            "Certificate: Certificate Registration",
            "Certificate registration monitoring",
        )
        .replace(  # API calls in AWS & Azure
            "Cloud Service: Cloud Service Disable",
            "Cloud API Logging; Cloud Audit Logging",
        )
        .replace(  # API calls in AWS & Azure
            "Cloud Service: Cloud Service Enumeration",
            "Cloud API Logging; Cloud Audit Logging",
        )
        .replace(  # API calls in AWS & Azure
            "Cloud Service: Cloud Service Modification",
            "Cloud API Logging; Cloud Audit Logging",
        )
        .replace(  # API calls in AWS & Azure
            "Cloud Storage: Cloud Storage Access",
            "Cloud API Logging; Cloud Audit Logging",
        )
        .replace(  # API calls in AWS & Azure
            "Cloud Storage: Cloud Storage Creation",
            "Cloud API Logging; Cloud Audit Logging",
        )
        .replace(  # API calls in AWS & Azure
            "Cloud Storage: Cloud Storage Deletion",
            "Cloud API Logging; Cloud Audit Logging",
        )
        .replace(  # API calls in AWS & Azure
            "Cloud Storage: Cloud Storage Enumeration",
            "Cloud API Logging; Cloud Audit Logging",
        )
        .replace(  # API calls in AWS & Azure
            "Cloud Storage: Cloud Storage Modification",
            "Cloud API Logging; Cloud Audit Logging",
        )
        .replace(  # API calls in Docker & Kubernetes
            "Container: Container Creation",
            "Cloud API Logging; Cloud Audit Logging; Command line logging",
        )
        .replace(  # API calls in Docker & Kubernetes
            "Container: Container Enumeration",
            "Cloud API Logging; Cloud Audit Logging; Command line logging",
        )
        .replace(  # API calls in Docker & Kubernetes
            "Container: Container Start",
            "Cloud API Logging; Cloud Audit Logging; Command line logging",
        )
        .replace("Domain Name: Active DNS", "Domain registration monitoring; Sysmon: 22; DNS Server Logs")
        .replace("Domain Name: Domain Registration", "Domain registration monitoring; Sysmon: 22; DNS Server Logs")
        .replace("Domain Name: Passive DNS", "Domain registration monitoring; Sysmon: 22; DNS Server Logs")
        .replace("Drive: Drive Access", "EventLog; setupapi.dev.log")
        .replace(
            "Drive: Drive Creation",
            "EventLog; setupapi.dev.log; Hardware layer monitoring",
        )
        .replace(
            "Driver: Driver Load",
            "CodeIntegrity EventLog: 3033;3063; Sysmon: 6",
        )
        .replace("Driver: Driver Metadata", "Sysmon")
        .replace(
            "File: File Access",
            "AppLocker EventLog: 8003;8004;8006;8007; Security EventLog: 4656;4663; Sysmon: 11",
        )
        .replace(
            "File: File Creation",
            "AppLocker EventLog: 8003;8004;8006;8007; Security EventLog: 4656;4663; Sysmon: 11",
        )
        .replace(
            "File: File Deletion",
            "Backup EventLog: 524; Security EventLog: 1100;1102;1104; System EventLog: 104; Sysmon: 23",
        )
        .replace(
            "File: File Metadata",
            "Artefact acquisition, Security EventLog: 4670;4719",
        )
        .replace(
            "File: File Modification",
            "Command line logging; Security EventLog: 4663;4670; Sysmon: 2",
        )
        .replace(  # include API calls in AWS & Azure
            "Firewall: Firewall Disable",
            "Command line logging; Security EventLog: 5025;5034; Firewall EventLog: 2003;2004;2005;2006",
        )
        .replace(  # include API calls in AWS & Azure
            "Firewall: Firewall Enumeration", "Command line logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Firewall: Firewall Metadata",
            "Firewall EventLog: 2003;2004;2005;2006",
        )
        .replace(  # include API calls in AWS & Azure
            "Firewall: Firewall Rule Modification",
            "Command line logging; Security EventLog: 4950; Firewall EventLog: 2003;2004;2005;2006",
        )
        .replace("Firmware: Firmware Modification", "Hardware layer monitoring")
        .replace(  # include API calls in AWS & Azure
            "Group: Group Enumeration",
            "Command line logging; Security EventLog: 4798;4799",
        )
        .replace(  # include API calls in AWS & Azure
            "Group: Group Metadata",
            "Command line logging; Windows event logs",
        )
        .replace(  # include API calls in AWS & Azure
            "Group: Group Modification",
            "Command line logging; Security EventLog: 4728;4732;4738;4670",
        )
        .replace(  # include API calls in AWS & Azure
            "Image: Image Creation", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Image: Image Deletion", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Image: Image Metadata", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Image: Image Modification", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Instance: Instance Creation", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Instance: Instance Deletion", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Instance: Instance Enumeration", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Instance: Instance Metadata", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Instance: Instance Modification", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Instance: Instance Start", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Instance: Instance Stop", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace("Internet Scan: Response Content", "netflow")
        .replace("Internet Scan: Response Metadata", "netflow")
        .replace(
            "Kernel: Kernel Module Load",
            "/lib/modules/*.ko logging",
        )
        .replace(  # include API calls in AWS & Azure
            "Logon Session: Logon Session Creation",
            "ADFS EventLog: 1200; Security EventLog: 4624;4769; Terminal Services EventLog: 1149; *nix /var/log",
        )
        .replace(  # include API calls in AWS & Azure
            "Logon Session: Logon Session Metadata",
            "Security EventLog: 4624;4634;4679",
        )
        .replace(
            "Malware Repository: Malware Content",
            "Artefact acquisition; Malware analysis",
        )
        .replace(
            "Malware Repository: Malware Metadata",
            "Artefact acquisition; Malware analysis",
        )
        .replace(
            "Module: Module Load",
            "PowerShellCore/Operational EventLog: 4103; Sysmon: 7",
        )
        .replace(
            "Named Pipe: Named Pipe Metadata", "Command line logging; Sysmon: 17;18"
        )
        .replace(
            "Network Share: Network Share Access",
            "Command line logging; Security EventLog: 5140;5145",
        )
        .replace(
            "Network Traffic: Network Connection Creation",
            "Process monitoring; Security EventLog: 5156; Sysmon: 3; Proxy logs; Zeek conn.log; WMI Activity EventLog",
        )
        .replace("Network Traffic: Network Traffic Content", "PCAP; Proxy logs")
        .replace("Network Traffic: Network Traffic Flow", "netflow")
        .replace("Operational Databases: Device Alarm", "")
        .replace("Operational Databases: Process History/Live Data", "")
        .replace("Operational Databases: Process/Event Alarm", "")
        .replace("Persona: Social Media", "Social media account monitoring")
        .replace(  # include API calls in AWS & Azure
            "Pod: Pod Creation",
            "Cloud API Logging; Cloud Audit Logging; Command line logging",
        )
        .replace(  # include API calls in AWS & Azure
            "Pod: Pod Enumeration",
            "Cloud API Logging; Cloud Audit Logging; Command line logging",
        )
        .replace(  # include API calls in AWS & Azure
            "Pod: Pod Modification",
            "Cloud API Logging; Cloud Audit Logging; Command line logging",
        )
        .replace(
            "Process: OS API Execution",
            "Process monitoring; Command line logging",
        )
        .replace("Process: Process Access", "Defender EventLog: 1006;1007;1116;1117; Sysmon: 10")
        .replace(
            "Process: Process Creation",
            "AppLocker EventLog: 8003;8004;8006;8007; Command line logging; Defender EventLog: 1116;1117; Security EventLog: 4688; Sysmon: 1; WMI Activity EventLog",
        )
        .replace(
            "Process: Process Metadata",
            "Sysmon",
        )
        .replace(
            "Process: Process Modification",
            "Artefact acquisition; Security EventLog: 4688; Sysmon: 1;8",
        )
        .replace("Process: Process Termination", "Security EventLog: 4689; Sysmon: 5")
        .replace(  # include API calls in AWS & Azure
            "Scheduled Job: Scheduled Job Creation",
            "Security EventLog: 106;4698;4700;4701;4702; TaskScheduler EventLog; *nix /var/log/cron; *nix /usr/*/cron",
        )
        .replace(  # include API calls in AWS & Azure
            "Scheduled Job: Scheduled Job Metadata",
            "Security EventLog: 4698; *nix /var/log/cron; *nix /usr/*/cron",
        )
        .replace(  # include API calls in AWS & Azure
            "Scheduled Job: Scheduled Job Modification",
            "Security EventLog: 4702; *nix /var/log/cron; *nix /usr/*/cron",
        )
        .replace(
            "Script: Script Execution",
            "PowerShellCore/Operational EventLog: 4104; Security EventLog: 4103;4104; WMI Activity EventLog",
        )
        .replace("Sensor Health: Host Status", "Host availability monitoring")
        .replace(
            "Service: Service Creation",
            "BITS EventLog: 59;60;16403; Command line logging; PrintService EventLog: 316;808;842; Security EventLog: 4697; System EventLog: 7045; *nix /var/log/daemon; *nix /usr/libexec/*/daemon",
        )
        .replace(
            "Service: Service Metadata",
            "Command line logging; System EventLog: 7036;7040; *nix /var/log/daemon; *nix /usr/libexec/*/daemon",
        )
        .replace(
            "Service: Service Modification",
            "Command line logging; System EventLog: 7040; *nix /var/log/daemon; *nix /usr/libexec/*/daemon",
        )
        .replace(  # include API calls in AWS & Azure
            "Snapshot: Snapshot Creation", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Snapshot: Snapshot Deletion", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Snapshot: Snapshot Enumeration", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Snapshot: Snapshot Modification", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "User Account: User Account Authentication",
            "Security EventLog: 4624;4625;4776;5379; *nix /var/log/audit/audit.log; *nix /var/log/auth.log; *nix /var/log/faillog; *nix /var/log/lastlog; *nix /var/log/syslog; *nix /var/log/tallylog; *nix /var/log/secure; *nix /etc/login.defs; *nix /etc/securetty",
        )
        .replace(  # include API calls in AWS & Azure
            "User Account: User Account Creation",
            "Security EventLog: 4720; *nix /etc/passwd logging",
        )
        .replace(  # include API calls in AWS & Azure
            "User Account: User Account Deletion",
            "Security EventLog: 4726; *nix /var/log/auth; *nix access/authentication",
        )
        .replace(  # include API calls in AWS & Azure
            "User Account: User Account Metadata",
            "",
        )
        .replace(  # include API calls in AWS & Azure
            "User Account: User Account Modification",
            "Security EventLog: 4670;4723;4724;4725;4728;4738; *nix /var/log/auth; *nix access/authentication",
        )
        .replace("User Interface: Permissions Request", "")
        .replace("User Interface: System Notifications", "")
        .replace("User Interface: System Settings", "")
        .replace(  # include API calls in AWS & Azure
            "Volume: Volume Creation", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Volume: Volume Deletion", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Volume: Volume Enumeration", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(  # include API calls in AWS & Azure
            "Volume: Volume Modification", "Cloud API Logging; Cloud Audit Logging"
        )
        .replace(
            "Web Credential: Web Credential Creation",
            "Security EventLog: 4769; System EventLog: 1200",
        )
        .replace(
            "Web Credential: Web Credential Usage",
            "System EventLog: 1202;4769",
        )
        .replace(
            "Windows Registry: Windows Registry Key Access",
            "Security EventLog: 4656;4657;4663",
        )
        .replace(
            "Windows Registry: Windows Registry Key Creation",
            "Security EventLog: 4656;4657;4663; Sysmon: 12;13;14",
        )
        .replace(
            "Windows Registry: Windows Registry Key Deletion",
            "Security EventLog: 4658; Sysmon: 12",
        )
        .replace(
            "Windows Registry: Windows Registry Key Modification",
            "Security EventLog: 4657;4719; Sysmon: 12;13;14",
        )
        .replace(
            "WMI: WMI Creation",
            "Security EventLog: 5861; WMI Activity EventLog; Sysmon: 19;20;21",
        )
    )
    # replacing data sources based on platforms
    if "Windows" in platforms and ("Linux" in platforms or "macOS" in platforms):
        logsource = (
            logsource.replace(
                "Command line logging",
                "Command line logging; PowerShellCore/Operational EventLog: 4104; *nix /var/log/*",
            )
            .replace(
                "Command: Command Execution",
                "Command line logging; PowerShellCore/Operational EventLog: 4104; *nix /var/log/*",
            )
            .replace("Drive: Drive Modification", "*nix /var/log/*")
        )
    if "Windows" in platforms:
        logsource = (
            logsource.replace(
                "Command line logging",
                "Command line logging; PowerShellCore/Operational EventLog: 4104",
            )
            .replace(
                "Command: Command Execution",
                "Command line logging; PowerShellCore/Operational EventLog: 4104",
            )
            .replace(
                "Drive: Drive Modification", "Windows event logs; setupapi.dev.log"
            )
        )
    if "Linux" in platforms or "macOS" in platforms:
        logsource = (
            logsource.replace("Command line logging", "*nix /var/log/*")
            .replace("Command: Command Execution", "*nix /var/log/*")
            .replace("Drive: Drive Modification", "*nix /var/log/*")
        )
    # replacing data sources based on technique_id
    if technique_id == "T1136.001":
        logsource = re.sub(r"', ''", r"', 'PowerShell Event', ''", logsource)
    if technique_id == "T1136.002":
        logsource = re.sub(
            r"Security EventLog: 4688", r"ADFS Event; SecurityAD Event", logsource
        )
    if technique_id == "T1558.001":
        logsource = re.sub(r"', ''", r"', 'ADFS Event', ''", logsource)
    # replacing data sources based on platform
    if "IaaS" in platforms:
        logsource = re.sub(
            r"Cloud Audit Logging",
            r"AWS CloudTrail",
            re.sub(r"Cloud API Logging", r"AWS CloudTrail", logsource),
        )
        if technique_id == "T1046":
            logsource = re.sub(
                r"AWS CloudTrail", r"AWS CloudTrail; AWS VPCFlow", logsource
            )
    if "Azure" in platforms or "IaaS" in platforms:
        logsource = re.sub(
            r"Cloud Audit Logging",
            r"Azure LogAnalytics; Azure Audit Logs",
            re.sub(
                r"Cloud API Logging", r"Azure LogAnalytics; Azure Audit Logs", logsource
            ),
        )
        if technique_id == "T1046":
            logsource = re.sub(
                r"Azure LogAnalytics",
                r"Azure LogAnalytics; Azure Network Flow Logs",
                logsource,
            )
    if "GCP" in platforms or "IaaS" in platforms:
        logsource = re.sub(
            r"Cloud Audit Logging",
            r"GCP Cloud Audit Logs",
            re.sub(r"Cloud API Logging", r"GCP Cloud Audit Logs", logsource),
        )
        if technique_id == "T1046":
            logsource = re.sub(
                r"GCP Cloud Audit Logs",
                r"GCP Cloud Audit Logs; GCP VPC Flow Logs",
                logsource,
            )
    if "Azure" not in platforms and "IaaS" not in platforms and "GCP" not in platforms:
        logsource = logsource.replace("Cloud Audit Logging", "")
    # replacing data sources based on technique_id and/or platform
    if evidence_type == "evt" or technique_id == "T1543.003":
        logsource = logsource.replace("Process monitoring", "")
    if (
        evidence_type == "evt"
        or technique_id == "T1021.006"
        or technique_id == "T1543.003"
        or technique_id == "T1550.002"
        or technique_id == "T1557.001"
    ):
        logsource = re.sub(r"\*nix [^,]+", r"", logsource)
        logsource = (
            logsource.replace("; , ", "; ")
            .replace(";', '", "', '")
            .strip()
            .strip(";")
            .replace(", ; ", "; ")
            .replace(", ", "; ")
            .replace("; ; ", "; ")
        )
    return logsource
