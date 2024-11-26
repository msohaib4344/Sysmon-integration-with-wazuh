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

<img width="960" alt="2024-10-28 01_52_25-Greenshot" src="https://github.com/user-attachments/assets/dd2a868b-f2fd-41a4-ae93-5b85faaa9837">

Command to check the file location: dir

<img width="826" alt="2" src="https://github.com/user-attachments/assets/00e5271f-4c74-4586-b7e4-f2986ab390a4">

You might encounter this error


<img width="826" alt="2" src="https://github.com/user-attachments/assets/4ac88251-0bbe-42ec-a905-b0d355056f41">

You need to go to notepad++ or any other software for your convenience. 
Change the version in you case it miight be different.

<img width="960" alt="4" src="https://github.com/user-attachments/assets/c8f2e723-d86e-445e-86ad-076635a2f50a">

Now let's check if it working. 
execute command: Sysmon64.exe -accepteula -i sysconfig.xml
<img width="590" alt="5" src="https://github.com/user-attachments/assets/7bf92eae-ad59-4cb8-a44a-a529bf648a7f">


### Testing the Configuration

To verify that Sysmon is functioning correctly with the new configuration, follow these steps:

1. Launch PowerShell.
2. Open the Event Viewer and navigate to:

```
Applications and Services Logs/Microsoft/Windows/Sysmon/Operational
```

<img width="590" alt="5" src="https://github.com/user-attachments/assets/f4df35c8-dc0b-4f35-91fb-45064a7b8011">


Now you have execute some commands like powershell.exe to test sysmon working: 
If you will follow the given the path you will see this log beacuse we just executed the command of powershell.exe

<img width="470" alt="7" src="https://github.com/user-attachments/assets/188d40aa-7ebb-47d1-b252-f2e3b1211681">


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

  Here you will put config file:

![8](https://github.com/user-attachments/assets/73b367b8-08c4-4eb5-a7ed-5270c394d998)


Go to servies of your computer and Navigate to services
Then Restart your wazuh agent:

<img width="960" alt="9" src="https://github.com/user-attachments/assets/f5f1be46-d9bd-4800-9bed-c91639f13cf8">


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

  Here is overview of this configuration:

<img width="960" alt="9" src="https://github.com/user-attachments/assets/445c0d57-35b6-424d-9d91-98e419ac810c">

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


![11](https://github.com/user-attachments/assets/fa06e3ed-b9c9-469e-9495-e8feca3efcd7)


![12](https://github.com/user-attachments/assets/d6a29488-7d2f-452a-872d-dc895e43b0d9)

