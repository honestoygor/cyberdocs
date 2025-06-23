# 🖥️ Server 1 Configurations
## Wazuh
### Installing Wazuh (All-in-one Installation)

- Download and run the Wazuh installation assistant.

```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Once the assistant finishes the installation, the output shows the  access credentials and a message that confirms that the installation was successful.

```
INFO: --- Summary ---
INFO: You can access the web interface https://<WAZUH_DASHBOARD_IP_ADDRESS>
    User: admin
    Password: <ADMIN_PASSWORD>
INFO: Installation finished.
```

You now have installed and configured Wazuh.

- Access the Wazuh web interface with `https://<WAZUH_DASHBOARD_IP_ADDRESS>` and your credentials:
    - **Username**: `admin`
    - **Password**: `<ADMIN_PASSWORD>`

When you access the Wazuh dashboard for the first time, the browser  shows a warning message stating that the certificate was not issued by a trusted authority. This is expected and the user has the option to accept the certificate as an exception or, alternatively, configure the system to use a certificate from a trusted authority.

### Extracting Wazuh Credentials

You can find the passwords for all the Wazuh indexer and Wazuh API users in the `wazuh-passwords.txt` file inside `wazuh-install-files.tar`. To print them, run the following command:

```bash
sudo tar -xvf wazuh-install-files.tar
```

If you want to uninstall the Wazuh central components, run the Wazuh installation assistant using the option `-u` or `–-uninstall`.

---

# 🖥️ Server 2 Configurations

## Java

Install required dependencies with the code below.

```bash
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release
```

### Java Installation

```bash
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```

## Cassandra

Cassandra Installation

```bash
wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
```

Open `cassandra.yaml` file

```bash
nano /etc/cassandra/cassandra.yaml
```

Find and configure the items in `cassandra.yml` by uncomment or change parameters below:

```bash
cluster_name: '[DESIRED_NAME]'
listen_address: [THEHIVE_SERVER_IP_ADDRESS]
rpc_address: [THEHIVE_SERVER_IP_ADDRESS]

# Under seed_provider change seeds:
seed_provider:
    # Addresses of hosts that are deemed contact points. 
    # Cassandra nodes use this list of hosts to find each other and learn
    # the topology of the ring.  You must change this if you are running
    # multiple nodes!
    - class_name: org.apache.cassandra.locator.SimpleSeedProvider
      parameters:
          # seeds is actually a comma-delimited list of addresses.
          # Ex: "<ip1>,<ip2>,<ip3>"
          - seeds: "[THEHIVE_SERVER_IP_ADDRESS]:7000"
```
You might need to delete some cassandra files in order to work with the new configuration.
```
systemctl stop cassandra.service
rm -rf /var/lib/cassandra/*
systemctl start cassandra.service
systemctl status cassandra.service
```
---

## Elasticsearch

### Elasticsearch Installation

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```

---

Open `elasticsearch.yml` file

```bash
nano /etc/elasticsearch/elasticsearch.yml
```

Configure the items in `elasticsearch.yml` by uncomment or change parameters below:

```yaml
cluster.name: thehive
node.name: node-1
network.host: [Machine IP address]
http.port: 9200

#If only working with only one node:
client.initial_master_nodes: ["node-1"] #If you have more identify how many will be working with.
#You would use discovery.seed_hosts to scale up elasticsearch
```

---

## TheHive
### TheHive Installation

```bash
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
```
Default Credentials on port 9000 credentials are 'admin@thehive.local' with a password of 'secret'

---

Check ownership and permission on thehive filesystem called `thp`:

```bash
ls -la /opt/thp
```

If root is owner and the one with permission we need to change that for thehive:

```bash
chown -R thehive:thehive /opt/thp
```

Verify changes on ownership and permission to thehive.

Open the `.conf` file by running:

```bash
sudo subl /etc/thehive/application.conf
```

Change the configurations below on the `.conf` file:
```bash
hostname = ["Machine IP Address"] #Under janusgraph storage parameter
cluster-name = Hongyr #For the Cassandra parameter
hostname = ["Machine IP Address"] #For the Elasticsearch parameter
application.baseUrl = "http://[Machine IP Address]:9000"
```

Start TheHive:
```bash
systemctl start thehive
systemctl enable thehive
```

<aside>

> ⚠️ Make sure Cassandra, Elasticsearch, and TheHive are running using `systemctl status` because TheHive won’t run if one of the services goes offline.
If you experience an error trying to login into TheHive with default credentials you will need to check Elasticsearch status and configurations:

```bash
systemctl status elasticsearch
```

If Elasticsearch isn’t down when you tried login you need to create a custom `.jvm` option file.

```bash
sudo subl /etc/elasticsearch/jvm.options.d/jvm.options
```

Once opened paste the code below:

```bash
—Dlog4j2.formatMsgNoLookups=true
—Xms4g
—Xmx4g
```

This will limit the memory usage from Java (currently to 4g, but you can set it lower if you still experience issues). Than restart Elasticsearch.

```bash
systemctl restart elasticsearch
```

</aside>

## Suricata
### Suricata Installation

For Ubuntu 24.04.2 LTS install via OISF PPA (Binary Package)

1. **Install prerequisites and add the PPA**
    
    ```bash
    sudo apt-get install -y software-properties-common
    sudo add-apt-repository ppa:oisf/suricata-stable
    sudo apt-get install jq
    sudo apt-get update
    ```
    This adds the OISF “suricata-stable” PPA, which always tracks the latest stable release ([docs.suricata.io](https://docs.suricata.io/en/latest/quickstart.html)).
    
2. **Install Suricata**
    
    ```bash
    sudo apt-get install suricata
    ```
    
3. **Verify the installation and service status**
    
    ```bash
    suricata --build-info
    sudo systemctl status suricata
    ```
    You should see your Suricata version and a “loaded”/“active (running)” status.
    

---

### Basic Post-Install Setup

1. **Identify your network interface**
    
    ```bash
    ip a s
    ```
    
    Note the name (e.g. `enp3s0`, `eth0`) and IP of the interface you want to monitor ([docs.suricata.io](https://docs.suricata.io/en/latest/quickstart.html)).
    
2. **Edit `/etc/suricata/suricata.yaml`**
    - Set `HOME_NET` to include your local networks (default includes RFC 1918).
    - Under `af-packet:` (or your chosen capture method), set:
        
        ```yaml
        af-packet:
          - interface: YOUR_INTERFACE_NAME
            cluster-id: 99
            cluster-type: cluster_flow
            defrag: yes
            tpacket-v3: yes
        ```
        
    - Under `pcap:` (or your chosen capture method), set:
        
        ```yaml
        pcap:
          - interface: YOUR_INTERFACE_NAME
        ```
        
    
    If you have custom rules you want to add to suricata, follow the step below.
    
    - Under `default-rule-path:` (or your chosen capture method), set:
        
        ```yaml
        default-rule-path: /var/lib/suricata/rules
        
        rule-files:
          - suricata.rules
          - /etc/suricata/rules/local.rules #Create the file and add below the default .rules file.
        ```
        
3. **Fetch and update rules**
    
    ```bash
    sudo suricata-update
    ```
    
    This downloads the latest Emerging Threats “ET Open” rule set into `/var/lib/suricata/rules`.
    
4. Add other rules sources
    
    <aside>
    You can check list of sources by:
    
    ```bash
    sudo suricata-update list-sources
    ```
    
    </aside>
    
    Choose the indexes you want:
    
    ```bash
    sudo suricata-update enable-source et/open
    sudo suricata-update enable-source oisf/trafficid
    sudo suricata-update
    sudo systemctl restart suricata
    ```
    

This downloads the latest Emerging Threats “ET Open” rule set into `/var/lib/suricata/rules`.

### Understanding source indexes use cases
These suricata source indexes are nothing more than curated rules that you can add on top of the default rules set when installing suricata, you are also able to configure user developed indexes which needs to be added before enabling.
<aside>
Here’s how to decide which feeds to pull in—and how to enable them—based on common deployment scenarios:

| Source | What it Gives You | When to Enable |
| --- | --- | --- |
| **et/open** | The full Emerging-Threats Open rule set (malware, exploits, reconnaissance, policy, etc.) | Almost always—this is your core IDS coverage. |
| **oisf/trafficid** | Protocol-identification rules (e.g. DNS, HTTP, SMB, TLS fingerprinting) | Usually - helps you classify and normalize traffic so other rules can match more accurately. |
| **abuse.ch/sslbl-blacklist** | IP blacklist for known malicious SSL/TLS servers | If you care about blocking or alerting on malicious C2 servers running TLS. |
| **abuse.ch/sslbl-ja3** | JA3 TLS fingerprint-based rules for malicious clients | If you want to detect malware that uses unique JA3 hashes (e.g. Cobalt Strike) even if it changes IPs. |
| **abuse.ch/sslbl-c2** | IP blacklist of known botnet C2 servers running SSL | If you’re especially worried about SSL-based botnets (e.g. TrickBot, Emotet). |
| **abuse.ch/feodotracker** | Feodo (aka Cridex) C2 IP blacklist | Only if Feodo/Cridex is a concern in your region—otherwise it’s a small subset of what `sslbl-c2` already covers. |
| **abuse.ch/urlhaus** | URLhaus malicious-URL detection rules | Great for spotting outbound web requests to known malware hosting or phishing sites. |
| **etnetera/aggressive** | Aggressive IP blacklist | Use with caution—high false-positive potential. Best in a honeynet or threat-intel lab, not on a production gateway. |
| **tgreen/hunting** | Custom “threat hunting” rules (anomaly-style, experimental) | For security teams that actively hunt; not recommended as defaults—they can be noisy. |
| **stamus/lateral** | Rules designed to catch lateral movement (SMB, WMI, RDP, etc.) | If you’re running Suricata on internal segments (e.g. a mirror port of your LAN) and want to detect “East-West” attacks. |
| **pawpatrules** | Miscellaneous community-contributed rules | Varies widely in quality—evaluate rule-by-rule before enabling in production. |
| **ptrules/open** | Positive Technologies’ open ruleset | Similar scope to ET Open; you can run side-by-side for additional coverage, but this often overlaps heavily with `et/open`. |
| **aleksibovellan/nmap** | Signatures to detect Nmap scans | Useful in high-security environments or honeypots to flag reconnaissance; optional in a home network where occasional scans are expected. |

---

## Recommendation for a Home/Small-Office Ubuntu Deployment

1. **Baseline**
    
    ```bash
    sudo suricata-update enable-source et/open
    sudo suricata-update enable-source oisf/trafficid
    ```
    
2. **Add Malware and C2 Feeds**
    
    ```bash
    sudo suricata-update enable-source abuse.ch/sslbl-blacklist
    sudo suricata-update enable-source abuse.ch/sslbl-c2
    sudo suricata-update enable-source abuse.ch/urlhaus
    ```
    
3. *(Optional)* **JA3-based malware detection**
    
    ```bash
    sudo suricata-update enable-source abuse.ch/sslbl-ja3
    ```
    
4. **Pull down and rebuild your rules**
    
    ```bash
    sudo suricata-update
    sudo systemctl restart suricata
    ```
    

That gives you solid, low-noise coverage against common threats.

---

## If You’re in a Larger/Enterprise Network

- **Internal Monitoring for Lateral Movement**: add `stamus/lateral`
- **Active Hunting**: consider `tgreen/hunting` (but vet rules carefully)
- **Extra Overlap**: you can pull in `ptrules/open` or `pawpatrules` for additional community content, but expect overlap and extra tuning.

---

### Performance Note

Every index you enable adds CPU and memory when Suricata parses packets. Start with your baseline (ET Open + TrafficID), confirm throughput is manageble, then add additional indexes one at a time, and monitor for false positives and resource impact before going “all-in.”

</aside>

1. **Enable and start the service**
    
    ```bash
    sudo systemctl enable suricata
    sudo systemctl restart suricata
    sudo journalctl -u suricata -f
    ```
    
    Or check logs directly:
    
    ```bash
    sudo tail -f /var/log/suricata/suricata.log
    sudo tail -f /var/log/suricata/stats.log
    sudo tail -f /var/log/suricata/eve.json | jq '.'
    ```
    
    You can parse `eve.json` into `jq` for better formatting of the log file:
    
    ```bash
    sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
    ```
