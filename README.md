# ALERTER

###  A script that will make Linux run as a Honeypot and alert for anomalies.

Identifying method used by adversaries by creating a custom honeypot for your needs from a range of common attack vectors.
Using automation enables quick deployment and analysis before company assets get compromised.

In addition this tool runs a counter scan on the adversaries that includes: origin
country, organization, contact information, open ports, services etc.
 
## Information
This tool is for educational purpose only, usage for attacking targets without prior mutual consent is illegal.
Developers assume no liability and are not responsible for any misuse or damage cause by this program.

## Features
- Fully Automating deployment.
- Service isolation using metasploit framework. 
- Port Service Scanning using Nmap.
- Additional OSINT tool for more details.
- Generate report in a text and web format.

# Installation 
Instructions on how to install *ALERTER*
```bash
git clone https://github.com/MtheEPIC/alerter.git
cd alerter
chmod u+x installer.sh 
sudo ./installer.sh
```
Instructions on how to check if the install was successful
```bash 
sudo ./installer.sh -q
```

# Execution 
Default scanning mode
```bash
chmod u+x alerter.sh 
sudo ./alerter.sh
```

# Screenshots
![Capture](https://github.com/MtheEPIC/alerter/assets/59831504/43382f71-251f-42a5-9033-64dac95a2416)

## License
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the **License** file for more details.
