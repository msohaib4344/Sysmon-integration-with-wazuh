# Sysmon-integration-with-wazuh
### Why We Need Integration of Wazuh and Syslogs

Integrating Wazuh with syslogs is important for several key reasons:

1. **Better Security Monitoring**:
    - Wazuh helps us monitor security events in real time. By connecting it with syslogs, we can analyze logs from different sources (like servers and applications) to quickly identify suspicious activities.
    
2. **Centralized Log Management**:

- Syslogs collect logs from multiple systems in one place. Integrating with Wazuh gives us a complete view of our environment, making it easier to manage and analyze these logs.
1. **Faster Incident Response**:

- This integration allows for quicker detection of security incidents. Wazuh can send alerts based on specific rules, enabling the security team to respond promptly.

1. **Regulatory Compliance**:

- Many industries have strict log management requirements. By integrating Wazuh with syslogs, we can ensure that we meet these standards and maintain detailed records of security events.

1. **Automated Threat Detection**:

- Wazuh automatically detects threats and manages vulnerabilities. With syslogs feeding more data into Wazuh, we enhance its ability to identify issues.

### Prerequisites for Integration

Before we start integrating Wazuh with syslogs, we need to meet the following requirements:

1. **Wazuh Manager Installed**:
    - Ensure the Wazuh manager is properly installed and configured on the designated server.
2. **Syslog Server Set Up**:
    - Set up a syslog server to collect logs from various sources. This server should be accessible by the Wazuh manager.
3. **Network Configuration**:
    - Make sure the network allows communication between the Wazuh manager and the syslog server. Check that firewalls permit the necessary traffic.
4. **Compatible Log Formats**:
    - Confirm that the log formats from the syslog server work well with Wazuh for proper analysis.
5. **Access Permissions**:
    - Ensure the Wazuh manager has the right permissions to access logs from the syslog server.

# Configurations in Windows

### Installation Steps

1. **Download Sysmon**:
    - Obtain the Sysmon tool from the official Sysinternals website.
2. **Create the XML File**:
    - Build the XML file as shown above or download it from a trusted source. Place this file in the same directory as the Sysmon binaries.
    
    ```
    <Sysmon schemaversion="3.30">
     <HashAlgorithms>md5</HashAlgorithms>
     <EventFiltering>
     <!--SYSMON EVENT ID 1 : PROCESS CREATION-->
     <ProcessCreate onmatch="include">
     <Image condition="contains">powershell.exe</Image>
     </ProcessCreate>
     <!--SYSMON EVENT ID 2 : FILE CREATION TIME RETROACTIVELY CHANGED IN THE FILESYSTEM-->
     <FileCreateTime onmatch="include"></FileCreateTime>
     <!--SYSMON EVENT ID 3 : NETWORK CONNECTION INITIATED-->
     <NetworkConnect onmatch="include"></NetworkConnect>
     <!--SYSMON EVENT ID 4 : RESERVED FOR SYSMON STATUS MESSAGES, THIS LINE IS INCLUDED FOR DOCUMENTATION PURPOSES ONLY-->
     <!--SYSMON EVENT ID 5 : PROCESS ENDED-->
     <ProcessTerminate onmatch="include"></ProcessTerminate>
     <!--SYSMON EVENT ID 6 : DRIVER LOADED INTO KERNEL-->
     <DriverLoad onmatch="include"></DriverLoad>
     <!--SYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS-->
     <ImageLoad onmatch="include"></ImageLoad>
     <!--SYSMON EVENT ID 8 : REMOTE THREAD CREATED-->
     <CreateRemoteThread onmatch="include"></CreateRemoteThread>
     <!--SYSMON EVENT ID 9 : RAW DISK ACCESS-->
     <RawAccessRead onmatch="include"></RawAccessRead>
     <!--SYSMON EVENT ID 10 : INTER-PROCESS ACCESS-->
     <ProcessAccess onmatch="include"></ProcessAccess>
     <!--SYSMON EVENT ID 11 : FILE CREATED-->
     <FileCreate onmatch="include"></FileCreate>
     <!--SYSMON EVENT ID 12 & 13 & 14 : REGISTRY MODIFICATION-->
     <RegistryEvent onmatch="include"></RegistryEvent>
     <!--SYSMON EVENT ID 15 : ALTERNATE DATA STREAM CREATED-->
     <FileCreateStreamHash onmatch="include"></FileCreateStreamHash>
     <PipeEvent onmatch="include"></PipeEvent>
     </EventFiltering>
    </Sysmon>
    
    ```
    

**Purpose of the XML Configuration File**

**Custom Configuration:**

The XML file allows you to customize what events Sysmon monitors and logs. Without it, Sysmon would use default settings, which might not capture all the activities you want to track.

### **Event Filtering:**

The file specifies which events to include or exclude. For example, in your XML, you specifically included logging for the creation of processes like powershell.exe. This filtering helps reduce noise in the logs, focusing only on relevant activities.

### Schema Versioning:

The schema version in the XML file ensures compatibility with the Sysmon version you are using. It defines the structure of the configuration and the events that can be monitored.
Impact of the XML Configuration

### Increased Visibility:

By configuring Sysmon to log specific events, you gain better visibility into system activities, making it easier to identify potentially malicious behavior, like unauthorized execution of scripts or processes.

### Improved Security Monitoring:

Customized logging helps in forensic analysis and security monitoring. If an incident occurs, the logs can provide valuable insights into what happened, when, and how.

### Resource Management:

Logging only necessary events helps conserve system resources and makes it easier to analyze the logs, as you won’t be overwhelmed with irrelevant data.

# Command Using CMD

- Open a Command Prompt with administrator privileges and execute the following command to install Sysmon with the custom configuration:

Sysmon64.exe -accepteula -i sysconfig.xml

![2024-10-28 01_52_25-Greenshot.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/db1ccdd4-a606-4ae0-bf53-7550ca60e3af/c1520e01-2ee1-47c1-b2ea-0b2b122548ee/2024-10-28_01_52_25-Greenshot.png)

![2024-10-28 03_01_17-Select Administrator_ Command Prompt.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/db1ccdd4-a606-4ae0-bf53-7550ca60e3af/7d62739b-0a09-4e73-9578-22b097490218/2024-10-28_03_01_17-Select_Administrator__Command_Prompt.png)

![2024-10-28 03_06_50-Greenshot.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/db1ccdd4-a606-4ae0-bf53-7550ca60e3af/13d09e5d-96c5-4dcf-899b-5729a491dc7b/2024-10-28_03_06_50-Greenshot.png)

![2024-10-28 03_10_43-Sysmon - File Explorer.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/db1ccdd4-a606-4ae0-bf53-7550ca60e3af/95c37e5d-ba60-421c-806f-c8e897904070/2024-10-28_03_10_43-Sysmon_-_File_Explorer.png)

![2024-10-28 03_15_38-ChatGPT.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/db1ccdd4-a606-4ae0-bf53-7550ca60e3af/9b86d54d-1aa4-4943-b3f2-7a5426cb440e/2024-10-28_03_15_38-ChatGPT.png)

### Testing the Configuration

To verify that Sysmon is functioning correctly with the new configuration, follow these steps:

1. Launch PowerShell.
2. Open the Event Viewer and navigate to:

```
Applications and Services Logs/Microsoft/Windows/Sysmon/Operational
```

![2024-10-28 03_24_05-Greenshot.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/db1ccdd4-a606-4ae0-bf53-7550ca60e3af/43170fa2-cdba-425b-9883-dfd83869c142/2024-10-28_03_24_05-Greenshot.png)

![2024-10-28 03_34_52-Event Properties - Event 1, Sysmon.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/db1ccdd4-a606-4ae0-bf53-7550ca60e3af/846f0794-647c-4b9e-94d1-307fdd0182ad/2024-10-28_03_34_52-Event_Properties_-_Event_1_Sysmon.png)

# **Configure Wazuh agent to monitor Sysmon events**

We assume the Wazuh agent is installed and running in the computer being monitored. It is necessary to tell this agent that we want to monitor **Sysmon events**. For that, we need to include this code as part of the configuration of the agent by modifying `ossec.conf` accordingly:

```
<group name="sysmon,">
 <rule id="255000" level="12">
 <if_group>sysmon_event1</if_group>
 <field name="sysmon.image">\\powershell.exe||\\.ps1||\\.ps2</field>
 <description>Sysmon - Event 1: Bad exe: $(sysmon.image)</description>
 <group>sysmon_event1,powershell_execution,</group>
 </rule>
</group>
```

### Overview of the Wazuh Agent Configuration Script

- **Purpose**: To enable the Wazuh agent to monitor Sysmon events related to PowerShell execution.
- **Event Monitoring**: The script specifies conditions under which to track processes such as `powershell.exe` and scripts with extensions `.ps1` and `.ps2`.
- **Custom Rule Definition**:
    - A rule with ID `255000` is defined to trigger when the specified conditions are met.
    - The rule is set with a high severity level (12) to indicate critical alerts.
- **Grouping**: Events are organized into the `sysmon_event1` group for better categorization and context.
- **Description**: The rule includes a description to clarify the nature of the detected event, helping in incident response.
- **Implementation**: The script needs to be added to the Wazuh agent's `ossec.conf` file, followed by a restart of the agent for the changes to take effect.

![2024-10-28 03_51_17-_ossec.conf - Notepad.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/db1ccdd4-a606-4ae0-bf53-7550ca60e3af/21e0a554-1ed4-472c-a9f7-59f82cec4d94/2024-10-28_03_51_17-_ossec.conf_-_Notepad.png)

![2024-10-28 03_52_38-Greenshot.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/db1ccdd4-a606-4ae0-bf53-7550ca60e3af/b3284966-9df9-4dbc-8bf6-12491e9f7ce9/2024-10-28_03_52_38-Greenshot.png)

# **Configure Wazuh manager**

A new rule needs to be added to `local_rules.xml` in the Wazuh manager to match the Sysmon event generated by the execution of Powershell. This rule will allow the manager to trigger an alert every time it gets this type of event.

```
<group name="sysmon,">
 <rule id="255000" level="12">
 <if_group>sysmon_event1</if_group>
 <field name="sysmon.image">\\powershell.exe||\\.ps1||\\.ps2</field>
 <description>Sysmon - Event 1: Bad exe: $(sysmon.image)</description>
 <group>sysmon_event1,powershell_execution,</group>
 </rule>
</group>
```

### Overview of the Wazuh Manager Configuration Script

- **Purpose**: To add a new rule in the `local_rules.xml` file of the Wazuh manager that monitors Sysmon events triggered by PowerShell execution.
- **Event Matching**: The rule specifically targets Sysmon Event ID 1, which corresponds to process creation.
- **Condition**: It checks if the `sysmon.image` field contains:
    - `\\\\powershell.exe`
    - Files with extensions `.ps1` and `.ps2`
- **Alert Triggering**:
    - Every time the Wazuh manager receives this type of event, it triggers an alert.
    - The alert level is set to 12, indicating a high severity, emphasizing its importance from a security perspective.
- **Grouping**: The rule is organized under the `sysmon_event1` group and categorized within the `powershell_execution` group for better context.
- **Customization**: This rule acts as a "child" rule of the existing Sysmon ruleset provided by Wazuh, allowing for tailored monitoring of PowerShell-related events.
- **Implementation**: To activate the rule, it must be added to the `local_rules.xml` file in the Wazuh manager, followed by a restart of the manager for the changes to take effect.

![2024-10-28 04_01_20-ossec-agent - File Explorer.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/db1ccdd4-a606-4ae0-bf53-7550ca60e3af/fd0a6500-68d4-428e-abbc-97fc1ea04747/2024-10-28_04_01_20-ossec-agent_-_File_Explorer.png)

### Restarted the Wazuh manager.

# Testing logs coming to Wazuh Dashboard

1. **Sysmon Event Generation**:
    - Sysmon (System Monitor) on Windows generates logs for specific system activities (e.g., process creation, network connections).
2. **Wazuh Agent Collection**:
    - The Wazuh agent, installed on the Windows system, collects these Sysmon logs from the Windows Event Log.
3. **Log Transmission to Wazuh Server**:
    - The Wazuh agent sends these collected logs to the Wazuh server for further processing.
4. **Parsing and Rule Application**:
    - Wazuh server parses the logs, extracting important fields.
    - It applies rules to identify potential security issues or suspicious behavior.
5. **Display in Wazuh Dashboard**:
    - Processed logs and any alerts generated are displayed in the Wazuh dashboard for monitoring and analysis by security teams.

This setup allows security teams to monitor Windows systems in real-time through Wazuh, using logs generated by Sysmon.




![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/db1ccdd4-a606-4ae0-bf53-7550ca60e3af/ccc38c6e-bef6-44e3-b920-e249b9b73519/image.png)

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/db1ccdd4-a606-4ae0-bf53-7550ca60e3af/d5d3c3e6-a39b-46f5-a12e-b3814fabad87/image.png)
