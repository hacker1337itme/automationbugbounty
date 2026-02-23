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
Here are 20 more creative and unconventional ways to use Subfinder:

## 13. **Supply Chain Attack Surface Mapping**
```bash
# Map third-party vendor dependencies
subfinder -d target.com -silent | while read sub; do
    # Extract all third-party domains from JavaScript and HTML
    curl -s "https://$sub" 2>/dev/null | grep -Eo '(https?://[^/"]+)' | 
    grep -v "$sub" | cut -d'/' -f3 | while read third_party; do
        if [[ ! -z "$third_party" ]]; then
            subfinder -d "$third_party" -silent | while read vendor_sub; do
                if host "$vendor_sub" | grep -q "$(dig +short $sub | head -1)"; then
                    echo "Shared infrastructure: $sub <-> $vendor_sub"
                fi
            done
        fi
    done
done
```

## 14. **Subdomain-Based Social Engineering Map**
```bash
# Create social engineering target map based on subdomain naming
subfinder -d company.com -silent | grep -Eo '([a-z]+)\.[a-z]+\.company\.com' | 
cut -d'.' -f1 | sort -u | while read prefix; do
    case "$prefix" in
        *hr|*people|*staff) echo "HR targets: $prefix.company.com" ;;
        *dev|*git|*code|*repo) echo "Developer targets: $prefix.company.com" ;;
        *pay|*invoice|*billing) echo "Finance targets: $prefix.company.com" ;;
        *admin|*manage|*portal) echo "Admin targets: $prefix.company.com" ;;
        *test|*staging|*dev*) echo "Potential weaker security: $prefix.company.com" ;;
    esac
done
```

## 15. **Geopolitical Risk Assessment**
```bash
# Identify subdomains hosted in high-risk jurisdictions
subfinder -d globalcorp.com -silent | while read sub; do
    ip=$(dig +short $sub | head -1)
    if [ ! -z "$ip" ]; then
        country=$(curl -s "http://ip-api.com/json/$ip" | jq -r '.countryCode')
        high_risk_countries=("CN" "RU" "IR" "KP" "SY" "VE")
        if [[ " ${high_risk_countries[@]} " =~ " ${country} " ]]; then
            echo "⚠️ HIGH RISK: $sub hosted in $country"
            # Check for sensitive data exposure
            curl -s "https://$sub/robots.txt" 2>/dev/null | grep -i "disallow" && 
            echo "  Potential sensitive paths exposed"
        fi
    fi
done
```

## 16. **Subdomain Pattern Analysis for Hidden Services**
```bash
# Find hidden development/staging environments by pattern matching
subfinder -d company.com -silent > all_subs.txt
patterns=("test" "dev" "staging" "uat" "qa" "beta" "alpha" "demo" "sandbox" "internal")
for pattern in "${patterns[@]}"; do
    # Look for subdomains that should exist but don't
    if ! grep -q "$pattern" all_subs.txt; then
        echo "Missing $pattern subdomain - checking if it exists but not in DNS..."
        for tld in com net org io co; do
            host "$pattern.company.$tld" &>/dev/null && 
            echo "Found: $pattern.company.$tld (not in standard enumeration)"
        done
    fi
done
```

## 17. **Subdomain-Based Incident Response Planning**
```bash
# Create incident response inventory with criticality scoring
subfinder -d bank.com -silent | while read sub; do
    criticality=0
    # Check for keywords indicating critical services
    if echo "$sub" | grep -E "bank|auth|login|pay|transfer|api"; then
        criticality=$((criticality + 10))
    fi
    # Check for regulatory implications
    if echo "$sub" | grep -E "compliance|audit|regulatory|report"; then
        criticality=$((criticality + 8))
    fi
    # Check for customer data
    if curl -s -I "https://$sub" 2>/dev/null | grep -i "set-cookie"; then
        criticality=$((criticality + 5))
    fi
    echo "$sub: Criticality Score $criticality"
done | sort -t: -k2 -rn > incident_response_priorities.txt
```

## 18. **Acoustic/Rhythmic Pattern Recognition**
```bash
# Find subdomains that sound like legitimate services (typosquatting detection)
subfinder -d company.com -silent | while read sub; do
    # Generate common typo variations
    echo "$sub" | sed 's/company/compnay/g; s/company/comapny/g; s/company/cmpany/g' | 
    while read typo; do
        if host "$typo" &>/dev/null; then
            echo "⚠️ Potential typosquatting: $typo"
            # Check if it's malicious
            curl -s "http://$typo" -I | grep -i "phish|bank|login|verify" && 
            echo "  MALICIOUS: $typo appears to be phishing"
        fi
    done
done
```

## 19. **Subdomain Metadata Correlation**
```bash
# Correlate subdomains with leaked credential databases
subfinder -d target.com -silent | while read sub; do
    # Check if subdomain appears in breach data (using haveibeenpwned API)
    breach_check=$(curl -s "https://haveibeenpwned.com/api/v3/breacheddomain/$sub" \
        -H "hibp-api-key: $HIBP_KEY" 2>/dev/null)
    if [ ! -z "$breach_check" ] && [ "$breach_check" != "[]" ]; then
        echo "⚠️ $sub appears in breach data: $breach_check"
    fi
    
    # Check archive.org for historical content changes
    archive_data=$(curl -s "https://archive.org/wayback/available?url=$sub")
    if echo "$archive_data" | grep -q "timestamp"; then
        first_seen=$(echo "$archive_data" | jq -r '.archived_snapshots.closest.timestamp')
        echo "$sub first appeared on web: $first_seen"
    fi
done
```

## 20. **Cross-Organization Subdomain Bridging**
```bash
# Find connections between organizations (M&A targets, partners, competitors)
companies=("companyA.com" "companyB.com" "companyC.com")
for company in "${companies[@]}"; do
    subfinder -d "$company" -silent > "${company}_subs.txt"
done

# Find shared infrastructure
for company1 in "${companies[@]}"; do
    for company2 in "${companies[@]}"; do
        if [ "$company1" != "$company2" ]; then
            while read sub1; do
                ip1=$(dig +short "$sub1" | head -1)
                while read sub2; do
                    ip2=$(dig +short "$sub2" | head -1)
                    if [ "$ip1" == "$ip2" ] && [ ! -z "$ip1" ]; then
                        echo "CONNECTION: $sub1 ($company1) and $sub2 ($company2) share IP $ip1"
                    fi
                done < "${company2}_subs.txt"
            done < "${company1}_subs.txt"
        fi
    done
done
```

## 21. **Subdomain-Based Market Intelligence**
```bash
# Track competitor expansion through subdomain analysis
competitors=("rival1.com" "rival2.com" "rival3.com")
for comp in "${competitors[@]}"; do
    subfinder -d "$comp" -silent | while read sub; do
        # Identify new market entries
        if echo "$sub" | grep -E "asia|europe|africa|launch|beta|new"; then
            echo "COMPETITOR INTELLIGENCE: $comp launching in new region: $sub"
            # Check hiring signals
            curl -s "https://$sub/careers" 2>/dev/null | grep -i "hiring|job|career" &&
            echo "  → Hiring activity detected at $sub"
        fi
    done
done
```

## 22. **Subdomain Resilience Testing**
```bash
# Test disaster recovery and failover configurations
subfinder -d company.com -silent > primary_subs.txt
# Simulate regional outage
for region in us eu asia; do
    echo "Testing $region outage scenario..."
    while read sub; do
        primary_ip=$(dig +short "$sub" | head -1)
        # Block region-specific IPs and test failover
        iptables -A INPUT -s "$primary_ip" -j DROP
        sleep 5
        failover_ip=$(dig +short "$sub" | head -1)
        if [ "$primary_ip" != "$failover_ip" ] && [ ! -z "$failover_ip" ]; then
            echo "✅ $sub has failover: $primary_ip → $failover_ip"
        fi
        iptables -D INPUT -s "$primary_ip" -j DROP
    done < primary_subs.txt
done
```

## 23. **Subdomain-Based Insider Threat Detection**
```bash
# Monitor for internal service exposure
subfinder -d company.com -silent | while read sub; do
    # Check for internal naming conventions
    if echo "$sub" | grep -E "internal|corp|private|office|staff|employee"; then
        echo "INTERNAL SERVICE EXPOSED: $sub"
        # Test authentication requirements
        response=$(curl -s -o /dev/null -w "%{http_code}" "https://$sub")
        if [ "$response" == "200" ]; then
            echo "  ⚠️ No authentication required!"
            # Check for sensitive info
            curl -s "https://$sub" | grep -i "confidential|internal use only|private" &&
            echo "  ⚠️ Sensitive internal data exposed!"
        fi
    fi
done
```

## 24. **Subdomain SEO/Reputation Analysis**
```bash
# Analyze subdomain authority and search engine ranking
subfinder -d company.com -silent | while read sub; do
    # Check Google PageRank (simplified)
    moz_rank=$(curl -s "https://moz.com/api/v2/metrics/url?url=$sub" \
        -H "Mozscape-Access-ID: $MOZ_ID" 2>/dev/null | jq '.page_authority')
    
    # Check backlinks
    backlinks=$(curl -s "https://api.majestic.com/api/json?app_api_key=$MAJESTIC_KEY&cmd=GetBackLinkData&item=$sub" | 
        jq '.DataTables.BackLinks.Count')
    
    echo "$sub: Page Authority: $moz_rank, Backlinks: $backlinks"
    
    # Alert on reputation drops
    if [ $moz_rank -lt 20 ] && [ $backlinks -lt 10 ]; then
        echo "⚠️ Low reputation subdomain that could be abused: $sub"
    fi
done
```

## 25. **Subdomain-Based Threat Hunting Queries**
```bash
# Create threat hunting queries for SIEM/SOAR platforms
subfinder -d company.com -silent | while read sub; do
    ip=$(dig +short "$sub" | head -1)
    
    # Splunk query
    echo "index=proxy sourcetype=access_combined url=*$sub* | stats count by src_ip" > "splunk_${sub}.spl"
    
    # Elasticsearch query
    echo "{\"query\":{\"wildcard\":{\"domain\":\"*$sub\"}}}" > "elastic_${sub}.json"
    
    # Sigma rule
    cat << EOF > "sigma_${sub}.yml"
title: Suspicious connection to $sub
logsource:
  category: network_connection
detection:
  selection:
    destination_hostname: '*$sub'
    destination_ip: '$ip'
  condition: selection
EOF
    
    echo "Generated hunting queries for $sub ($ip)"
done
```

## 26. **Subdomain Lifecycle Cost Analysis**
```bash
# Estimate infrastructure costs based on subdomain patterns
subfinder -d startup.com -silent | while read sub; do
    cname=$(dig +short CNAME "$sub")
    cost=0
    
    # AWS services
    if [[ $cname == *"amazonaws.com"* ]]; then
        if [[ $cname == *"s3"* ]]; then
            cost=$((cost + 25)) # S3 bucket monthly cost
        elif [[ $cname == *"cloudfront"* ]]; then
            cost=$((cost + 50)) # CloudFront distribution
        fi
    fi
    
    # Heroku
    if [[ $cname == *"herokuapp.com"* ]]; then
        cost=$((cost + 25)) # Heroku dyno
    fi
    
    # Shopify
    if [[ $cname == *"myshopify.com"* ]]; then
        cost=$((cost + 29)) # Shopify basic plan
    fi
    
    echo "$sub: Estimated monthly cost \$$cost"
done | awk '{sum+=$NF} END {print "Total estimated infrastructure cost: $" sum}'
```

## 27. **Subdomain Acquisition Opportunity Finder**
```bash
# Find expiring/available subdomains for brand protection
subfinder -d company.com -silent | while read sub; do
    # Check expiration dates for domain registrations
    expiry_date=$(whois "$sub" | grep -i "expir" | head -1 | grep -Eo '[0-9]{4}-[0-9]{2}-[0-9]{2}')
    if [ ! -z "$expiry_date" ]; then
        days_until_expiry=$(( ($(date -d "$expiry_date" +%s) - $(date +%s)) / 86400 ))
        
        if [ $days_until_expiry -lt 30 ] && [ $days_until_expiry -gt 0 ]; then
            echo "⚠️ $sub expiring in $days_until_expiry days - RENEW IMMEDIATELY"
        elif [ $days_until_expiry -lt 0 ]; then
            # Check if domain is available
            if whois "$sub" 2>&1 | grep -q "No match\|NOT FOUND"; then
                echo "🟢 $sub is AVAILABLE for registration!"
            fi
        fi
    fi
done
```

## 28. **Subdomain DNS Health Check**
```bash
# Comprehensive DNS health monitoring
subfinder -d company.com -silent > all_subs.txt

echo "DNS Health Report - $(date)" > dns_health.txt
echo "=====================" >> dns_health.txt

while read sub; do
    # Check DNSSEC
    dnssec_status=$(dig +dnssec "$sub" | grep -i "ad;" | wc -l)
    if [ $dnssec_status -eq 0 ]; then
        echo "❌ $sub: DNSSEC not enabled" >> dns_health.txt
    fi
    
    # Check SPF records
    spf=$(dig TXT "$sub" | grep -i "v=spf1")
    if [ -z "$spf" ]; then
        echo "⚠️ $sub: No SPF record found" >> dns_health.txt
    fi
    
    # Check DMARC
    dmarc=$(dig TXT "_dmarc.$sub" | grep -i "v=DMARC")
    if [ -z "$dmarc" ]; then
        echo "⚠️ $sub: No DMARC record found" >> dns_health.txt
    fi
    
    # Check DNS response time
    response_time=$(dig "$sub" | grep "Query time:" | awk '{print $4}')
    if [ $response_time -gt 100 ]; then
        echo "⚠️ $sub: Slow DNS response (${response_time}ms)" >> dns_health.txt
    fi
    
done < all_subs.txt
```

## 29. **Subdomain Watering Hole Detection**
```bash
# Identify subdomains that could be used for watering hole attacks
subfinder -d company.com -silent | while read sub; do
    # Check for outdated software
    server_header=$(curl -s -I "https://$sub" 2>/dev/null | grep -i "^server:" | cut -d' ' -f2-)
    
    # Version detection and vulnerability checking
    if echo "$server_header" | grep -q "Apache/2.2"; then
        echo "⚠️ OUTDATED: $sub running $server_header (known vulnerabilities)"
    elif echo "$server_header" | grep -q "PHP/5"; then
        echo "⚠️ OUTDATED: $sub running $server_header (end of life)"
    fi
    
    # Check for vulnerable JS libraries
    curl -s "https://$sub" 2>/dev/null | grep -o 'src="[^"]*\.js"' | cut -d'"' -f2 | while read js; do
        full_url="https://$sub$js"
        curl -s "$full_url" | grep -E "jquery-1\.[0-9]|angular-1\.[0-9]|bootstrap-3\.[0-9]" && 
        echo "⚠️ VULNERABLE JS: $full_url uses outdated library"
    done
done
```

## 30. **Subdomain-Based Threat Intelligence Feeds**
```bash
# Create custom threat intelligence feeds
subfinder -d target.com -silent | while read sub; do
    ip=$(dig +short "$sub" | head -1)
    
    # Generate STIX format indicators
    cat << EOF >> "threat_intel_$(date +%Y%m%d).stix"
{
  "type": "indicator",
  "spec_version": "2.1",
  "name": "Observed subdomain $sub",
  "pattern": "[domain-name:value = '$sub'] OR [ipv4-addr:value = '$ip']",
  "valid_from": "$(date -Iseconds)",
  "labels": ["subdomain", "observed", "$(echo $sub | cut -d. -f1)"]
}
EOF

    # Add to MISP events
    curl -X POST -H "Authorization: $MISP_KEY" -H "Content-Type: application/json" \
        -d "{\"Attribute\":{\"value\":\"$sub\",\"type\":\"domain\",\"category\":\"Network activity\"}}" \
        "https://misp.local/attributes/add"
    
    echo "Added $sub to threat intelligence feeds"
done
```

## 31. **Subdomain Encryption Standards Audit**
```bash
# Audit TLS/SSL configurations across all subdomains
subfinder -d bank.com -silent | while read sub; do
    echo "Auditing $sub..."
    
    # Get TLS version and cipher info
    tls_info=$(echo | openssl s_client -connect "$sub:443" -tls1_3 2>/dev/null)
    
    # Check TLS version
    if echo "$tls_info" | grep -q "TLSv1.3"; then
        tls_score=10
    elif echo "$tls_info" | grep -q "TLSv1.2"; then
        tls_score=8
    elif echo "$tls_info" | grep -q "TLSv1.1"; then
        tls_score=4
        echo "⚠️ $sub using outdated TLSv1.1"
    else
        tls_score=0
        echo "❌ $sub using insecure TLS/SSL"
    fi
    
    # Check certificate strength
    cert_info=$(echo | openssl s_client -connect "$sub:443" 2>/dev/null | openssl x509 -text)
    key_length=$(echo "$cert_info" | grep "Public-Key:" | grep -Eo '[0-9]+')
    if [ $key_length -lt 2048 ]; then
        echo "⚠️ $sub using weak key length ($key_length bits)"
        tls_score=$((tls_score - 3))
    fi
    
    # Check HSTS
    hsts=$(curl -s -I "https://$sub" | grep -i "strict-transport-security")
    if [ -z "$hsts" ]; then
        echo "⚠️ $sub missing HSTS header"
        tls_score=$((tls_score - 2))
    fi
    
    echo "$sub: TLS Score $tls_score/10" >> tls_audit_results.txt
done
```

## 32. **Subdomain Dependency Mapping for Disaster Recovery**
```bash
# Create complete dependency graph for DR planning
subfinder -d company.com -silent > live_subs.txt

echo "digraph Dependencies {" > deps.dot
while read sub; do
    # Find all external resources this subdomain depends on
    curl -s "https://$sub" 2>/dev/null | grep -Eo '(https?://[^/"]+)' | 
    grep -v "$sub" | cut -d'/' -f3 | while read dep; do
        echo "  \"$sub\" -> \"$dep\";" >> deps.dot
    done
    
    # Find IP dependencies
    ip=$(dig +short "$sub" | head -1)
    if [ ! -z "$ip" ]; then
        echo "  \"$sub\" -> \"$ip\";" >> deps.dot
    fi
done < live_subs.txt
echo "}" >> deps.dot

# Generate visual graph
dot -Tpng deps.dot -o dependency_graph.png
echo "Dependency graph generated: dependency_graph.png"
```

