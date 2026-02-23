# automationbugbounty
automationbugbounty


## 1. **Target Validation & Monitoring**
```bash
# Monitor for newly acquired domains by competitors/partners
subfinder -d targetcompany.com -silent | while read sub; do
    whois $sub | grep -i "creation date" | while read date; do
        if [[ $(date -d "$date" +%s) -gt $(date -d "30 days ago" +%s) ]]; then
            echo "New domain: $sub - Created: $date"
        fi
    done
done
```

## 2. **Infrastructure Fingerprinting Through Subdomain Patterns**
```bash
# Identify cloud providers and hosting patterns
subfinder -d target.com -silent | while read host; do
    nslookup $host | grep -E "amazonaws|azure|googleusercontent|digitalocean" && 
    echo "$host is cloud-hosted"
done | sort -u
```

## 3. **Historical Technology Tracking**
```bash
# Track technology changes over time
subfinder -d company.com -silent -o subs.txt
for sub in $(cat subs.txt); do
    # Check if the subdomain was previously hosting different tech
    waybackurls $sub | head -100 | while read url; do
        curl -s -I $url | grep -i "server:" | sed "s/^/$sub historically used: /"
    done
done
```

## 4. **Attack Surface Visualization for Acquisitions**
```bash
# When companies acquire other companies, map overlapping infrastructure
acquisitions=("acquired1.com" "acquired2.com" "acquired3.com")
for domain in "${acquisitions[@]}"; do
    subfinder -d $domain -silent | while read sub; do
        # Check if any infrastructure is shared with parent company
        if host $sub | grep -q "$(dig +short parent-company.com | head -1)"; then
            echo "Shared infrastructure: $sub from $domain"
        fi
    done
done
```

## 5. **Geolocation-Based Subdomain Discovery**
```bash
# Discover region-specific deployments
subfinder -d globalcompany.com -silent | grep -E "(eu|us|asia|africa|sa|au)" | while read sub; do
    ip=$(dig +short $sub | head -1)
    if [ ! -z "$ip" ]; then
        curl -s "http://ip-api.com/json/$ip" | jq '.country, .regionName, .city'
        echo "$sub located in $country"
    fi
done
```

## 6. **Certificate Transparency Mining for Acquired IPs**
```bash
# Find new subdomains based on recently acquired IP ranges
for ip in $(cat acquired_ip_ranges.txt); do
    # Use crt.sh to find certificates issued to IP
    curl -s "https://crt.sh/?q=$ip&output=json" | jq -r '.[].name_value' | 
    while read domain; do
        subfinder -d $domain -silent
    done
done
```

## 7. **Subdomain Reputation Monitoring**
```bash
# Monitor for subdomains that might be compromised or malicious
subfinder -d target.com -silent | while read sub; do
    # Check VirusTotal for detections
    vt_result=$(curl -s "https://www.virustotal.com/api/v3/domains/$sub" \
        -H "x-apikey: $VT_API_KEY" | jq '.data.attributes.last_analysis_stats.malicious')
    if [ $vt_result -gt 0 ]; then
        echo "⚠️ Potential malicious subdomain: $sub (Detections: $vt_result)"
    fi
    
    # Check SSL certificate issues
    if ! echo | openssl s_client -connect $sub:443 2>/dev/null | openssl x509 -noout -checkend 2592000; then
        echo "⚠️ SSL certificate expiring soon: $sub"
    fi
done
```

## 8. **Subdomain Hierarchy Mapping**
```bash
# Create dependency tree of subdomains
subfinder -d company.com -silent | while read sub; do
    # Find which main subdomains are required for functionality
    if curl -s -I "https://$sub" | grep -q "200\|301\|302"; then
        # Extract all subdomain references in JavaScript
        curl -s "https://$sub" | grep -Eo '(http|https)://[^/"]+' | 
        grep -v $sub | sort -u | while read ref; do
            echo "$sub depends on $ref"
        done
    fi
done
```

## 9. **Dark Web Monitoring for Subdomains**
```bash
# Combine with dark web search engines
subfinder -d target.com -silent | while read sub; do
    # Search for mentions in Ahmia or other dark web indexes
    curl -s "https://ahmia.fi/search/?q=$sub" | grep -i "$sub" &&
    echo "⚠️ $sub mentioned on dark web: $result"
done
```

## 10. **Subdomain Takeover Probability Scoring**
```bash
# Calculate takeover probability score for each subdomain
subfinder -d target.com -silent | while read sub; do
    score=0
    # Check CNAME records pointing to unused services
    cname=$(dig +short CNAME $sub)
    if [[ $cname == *"amazonaws"* ]] && ! host $cname &>/dev/null; then
        score=$((score + 50))
        echo "AWS S3 bucket potentially available: $sub"
    fi
    if [[ $cname == *"github"* ]] && ! host $cname &>/dev/null; then
        score=$((score + 40))
        echo "GitHub Pages site potentially available: $sub"
    fi
    if [ $score -gt 70 ]; then
        echo "HIGH RISK: $sub (Score: $score)"
    fi
done
```

## 11. **Recursive Trust Discovery**
```bash
# Find third-party services that trust your target
subfinder -d target.com -silent | while read sub; do
    # Check for OAuth redirect URIs
    curl -s "https://$sub/robots.txt" 2>/dev/null | grep -i "disallow" &&
    echo "$sub has sensitive paths"
    
    # Check for exposed .well-known endpoints
    curl -s "https://$sub/.well-known/oauth-authorization-server" 2>/dev/null | 
    jq -r '.issuer, .authorization_endpoint' 2>/dev/null | while read endpoint; do
        echo "OAuth endpoint found at $sub: $endpoint"
    done
done
```

## 12. **Subdomain Lifecycle Analysis**
```bash
# Track subdomain DNS changes over time
subfinder -d company.com -silent -o today.txt
diff yesterday.txt today.txt | while read line; do
    if [[ $line == ">"* ]]; then
        new_sub=$(echo $line | cut -d' ' -f2-)
        echo "🟢 New subdomain discovered: $new_sub"
        # Immediately scan new subdomain
        nmap -p80,443,8080,8443 $new_sub
    elif [[ $line == "<"* ]]; then
        dead_sub=$(echo $line | cut -d' ' -f2-)
        echo "🔴 Subdomain no longer resolving: $dead_sub"
    fi
done
```
