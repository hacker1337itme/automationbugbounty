#!/bin/bash

# Subfinder Automation Script with Interactive Menu
# Author: Security Team
# Version: 2.0

# Color codes for better visualization
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
OUTPUT_DIR="subfinder_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CONFIG_FILE=""
PROVIDER_CONFIG=""
RESOLVERS=""
RATE_LIMIT=""
THREADS="10"
TIMEOUT="30"
MAX_TIME="10"
CMD="subfinder"  # Initialize command

# Function to display banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                   SUBFINDER AUTOMATION                     ║"
    echo "║                    Interactive Menu v2.0                    ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to display main menu
show_main_menu() {
    echo -e "${YELLOW}Main Menu:${NC}"
    echo "1) Single Domain Enumeration"
    echo "2) Multiple Domains from File"
    echo "3) Advanced Options"
    echo "4) Source Management"
    echo "5) Output Configuration"
    echo "6) Performance Settings"
    echo "7) Update & Version Info"
    echo "8) List Available Sources"
    echo "9) Help & Examples"
    echo "0) Exit"
    echo ""
    echo -e "${BLUE}Select an option [0-9]:${NC} "
}

# Function to reset command
reset_command() {
    CMD="subfinder"
    # Reapply global settings
    if [ ! -z "$CONFIG_FILE" ]; then
        CMD="$CMD -config $CONFIG_FILE"
    fi
    if [ ! -z "$PROVIDER_CONFIG" ]; then
        CMD="$CMD -pc $PROVIDER_CONFIG"
    fi
    if [ ! -z "$RESOLVERS" ]; then
        CMD="$CMD -r $RESOLVERS"
    fi
    if [ ! -z "$RATE_LIMIT" ]; then
        CMD="$CMD -rl $RATE_LIMIT"
    fi
    if [ ! -z "$THREADS" ]; then
        CMD="$CMD -t $THREADS"
    fi
    if [ ! -z "$TIMEOUT" ]; then
        CMD="$CMD -timeout $TIMEOUT"
    fi
    if [ ! -z "$MAX_TIME" ]; then
        CMD="$CMD -max-time $MAX_TIME"
    fi
}

# Function for single domain enumeration
single_domain() {
    show_banner
    echo -e "${GREEN}=== Single Domain Enumeration ===${NC}"
    read -p "Enter domain (e.g., example.com): " DOMAIN
    
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}Domain cannot be empty!${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    reset_command
    CMD="$CMD -d $DOMAIN"
    
    # Ask for additional options
    echo -e "\n${YELLOW}Additional Options:${NC}"
    read -p "Enable active subdomain discovery? (y/n): " ACTIVE
    if [[ "$ACTIVE" == "y" || "$ACTIVE" == "Y" ]]; then
        CMD="$CMD -active"
        
        read -p "Include IP addresses? (y/n): " INCLUDE_IP
        if [[ "$INCLUDE_IP" == "y" || "$INCLUDE_IP" == "Y" ]]; then
            CMD="$CMD -ip"
        fi
    fi
    
    read -p "Enable JSON output? (y/n): " JSON_OUT
    if [[ "$JSON_OUT" == "y" || "$JSON_OUT" == "Y" ]]; then
        CMD="$CMD -json"
    fi
    
    read -p "Output to file? (y/n): " OUTPUT_FILE
    if [[ "$OUTPUT_FILE" == "y" || "$OUTPUT_FILE" == "Y" ]]; then
        mkdir -p "$OUTPUT_DIR"
        OUTPUT_FILENAME="${OUTPUT_DIR}/${DOMAIN}_${TIMESTAMP}.txt"
        if [[ "$JSON_OUT" == "y" || "$JSON_OUT" == "Y" ]]; then
            OUTPUT_FILENAME="${OUTPUT_DIR}/${DOMAIN}_${TIMESTAMP}.json"
        fi
        CMD="$CMD -o $OUTPUT_FILENAME"
        echo -e "${GREEN}Output will be saved to: $OUTPUT_FILENAME${NC}"
    fi
    
    execute_command
}

# Function for multiple domains
multiple_domains() {
    show_banner
    echo -e "${GREEN}=== Multiple Domains Enumeration ===${NC}"
    read -p "Enter path to domain list file: " DOMAIN_LIST
    
    if [ ! -f "$DOMAIN_LIST" ]; then
        echo -e "${RED}File not found: $DOMAIN_LIST${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    reset_command
    CMD="$CMD -dL $DOMAIN_LIST"
    
    # Create output directory
    read -p "Output directory for results [default: $OUTPUT_DIR]: " CUSTOM_OUTPUT_DIR
    if [ ! -z "$CUSTOM_OUTPUT_DIR" ]; then
        OUTPUT_DIR="$CUSTOM_OUTPUT_DIR"
    fi
    mkdir -p "$OUTPUT_DIR"
    CMD="$CMD -oD $OUTPUT_DIR"
    echo -e "${GREEN}Results will be saved in: $OUTPUT_DIR${NC}"
    
    # Ask for additional options
    echo -e "\n${YELLOW}Additional Options:${NC}"
    read -p "Enable active subdomain discovery? (y/n): " ACTIVE
    if [[ "$ACTIVE" == "y" || "$ACTIVE" == "Y" ]]; then
        CMD="$CMD -active"
    fi
    
    read -p "Enable JSON output? (y/n): " JSON_OUT
    if [[ "$JSON_OUT" == "y" || "$JSON_OUT" == "Y" ]]; then
        CMD="$CMD -json"
    fi
    
    execute_command
}

# Function to execute command
execute_command() {
    echo -e "\n${CYAN}Executing command:${NC}"
    echo -e "${YELLOW}$CMD${NC}\n"
    
    read -p "Proceed with execution? (y/n): " CONFIRM
    if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
        echo -e "${GREEN}Running subfinder...${NC}\n"
        eval $CMD
        echo -e "\n${GREEN}Enumeration completed!${NC}"
    else
        echo -e "${YELLOW}Command execution cancelled.${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Function for advanced options
advanced_options() {
    while true; do
        show_banner
        echo -e "${PURPLE}=== Advanced Options ===${NC}"
        echo "Current command: ${CYAN}$CMD${NC}"
        echo ""
        echo "1) Set match patterns (include specific subdomains)"
        echo "2) Set filter patterns (exclude specific subdomains)"
        echo "3) Configure resolvers"
        echo "4) Set proxy"
        echo "5) Set custom timeout/max-time"
        echo "6) Reset advanced options"
        echo "7) Back to main menu"
        echo ""
        
        read -p "Select option: " ADV_OPTION
        
        case $ADV_OPTION in
            1)
                read -p "Enter match patterns (comma-separated or file path): " MATCH
                CMD="$CMD -match $MATCH"
                echo -e "${GREEN}Match pattern set!${NC}"
                sleep 1
                ;;
            2)
                read -p "Enter filter patterns (comma-separated or file path): " FILTER
                CMD="$CMD -filter $FILTER"
                echo -e "${GREEN}Filter pattern set!${NC}"
                sleep 1
                ;;
            3)
                echo "Resolver options:"
                echo "1) Use comma-separated resolvers"
                echo "2) Use resolver file"
                read -p "Select option: " RESOLVER_OPT
                
                case $RESOLVER_OPT in
                    1)
                        read -p "Enter resolvers (comma-separated, e.g., 8.8.8.8,1.1.1.1): " RESOLVERS
                        CMD="$CMD -r $RESOLVERS"
                        ;;
                    2)
                        read -p "Enter resolver file path: " RESOLVER_FILE
                        if [ -f "$RESOLVER_FILE" ]; then
                            CMD="$CMD -rL $RESOLVER_FILE"
                        else
                            echo -e "${RED}File not found!${NC}"
                        fi
                        ;;
                esac
                echo -e "${GREEN}Resolvers configured!${NC}"
                sleep 1
                ;;
            4)
                read -p "Enter proxy URL (e.g., http://127.0.0.1:8080): " PROXY
                CMD="$CMD -proxy $PROXY"
                echo -e "${GREEN}Proxy configured!${NC}"
                sleep 1
                ;;
            5)
                read -p "Set timeout in seconds [default: 30]: " NEW_TIMEOUT
                if [ ! -z "$NEW_TIMEOUT" ]; then
                    TIMEOUT="$NEW_TIMEOUT"
                    CMD="$CMD -timeout $TIMEOUT"
                fi
                
                read -p "Set max time in minutes [default: 10]: " NEW_MAX_TIME
                if [ ! -z "$NEW_MAX_TIME" ]; then
                    MAX_TIME="$NEW_MAX_TIME"
                    CMD="$CMD -max-time $MAX_TIME"
                fi
                echo -e "${GREEN}Timeout settings updated!${NC}"
                sleep 1
                ;;
            6)
                reset_command
                echo -e "${GREEN}Advanced options reset!${NC}"
                sleep 1
                ;;
            7)
                break
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                sleep 1
                ;;
        esac
    done
}

# Function for source management
source_management() {
    while true; do
        show_banner
        echo -e "${BLUE}=== Source Management ===${NC}"
        echo "Current command: ${CYAN}$CMD${NC}"
        echo ""
        echo "1) Use all sources (-all)"
        echo "2) Use specific sources"
        echo "3) Exclude specific sources"
        echo "4) Use recursive sources only"
        echo "5) Set source rate limits"
        echo "6) Reset source options"
        echo "7) Back to main menu"
        echo ""
        
        read -p "Select option: " SRC_OPTION
        
        case $SRC_OPTION in
            1)
                CMD="$CMD -all"
                echo -e "${GREEN}All sources enabled!${NC}"
                sleep 1
                ;;
            2)
                read -p "Enter sources (comma-separated, e.g., crtsh,github): " SOURCES
                CMD="$CMD -s $SOURCES"
                echo -e "${GREEN}Specific sources configured!${NC}"
                sleep 1
                ;;
            3)
                read -p "Enter sources to exclude (comma-separated): " EXCLUDE
                CMD="$CMD -es $EXCLUDE"
                echo -e "${GREEN}Sources excluded!${NC}"
                sleep 1
                ;;
            4)
                CMD="$CMD -recursive"
                echo -e "${GREEN}Recursive sources only!${NC}"
                sleep 1
                ;;
            5)
                read -p "Enter source rate limits (e.g., hackertarget=10/s,shodan=15/s): " RATE_LIMITS
                CMD="$CMD -rls $RATE_LIMITS"
                echo -e "${GREEN}Rate limits configured!${NC}"
                sleep 1
                ;;
            6)
                # Remove source-related flags
                CMD=$(echo "$CMD" | sed -E 's/ -all| -s [^ ]*| -es [^ ]*| -recursive| -rls [^ ]*//g')
                echo -e "${GREEN}Source options reset!${NC}"
                sleep 1
                ;;
            7)
                break
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                sleep 1
                ;;
        esac
    done
}

# Function for output configuration
output_config() {
    while true; do
        show_banner
        echo -e "${GREEN}=== Output Configuration ===${NC}"
        echo "Current command: ${CYAN}$CMD${NC}"
        echo ""
        echo "1) Set output file"
        echo "2) Set output directory (for multiple domains)"
        echo "3) Toggle silent mode"
        echo "4) Toggle verbose mode"
        echo "5) Toggle color output"
        echo "6) Exclude IPs from output"
        echo "7) Collect sources in JSON output"
        echo "8) Reset output options"
        echo "9) Back to main menu"
        echo ""
        
        read -p "Select option: " OUT_OPTION
        
        case $OUT_OPTION in
            1)
                read -p "Enter output filename: " OUTFILE
                CMD="$CMD -o $OUTFILE"
                echo -e "${GREEN}Output file set to $OUTFILE!${NC}"
                sleep 1
                ;;
            2)
                read -p "Enter output directory: " OUTDIR
                mkdir -p "$OUTDIR"
                CMD="$CMD -oD $OUTDIR"
                echo -e "${GREEN}Output directory set to $OUTDIR!${NC}"
                sleep 1
                ;;
            3)
                if [[ "$CMD" == *"-silent"* ]]; then
                    CMD=$(echo "$CMD" | sed 's/ -silent//g')
                    echo -e "${YELLOW}Silent mode disabled!${NC}"
                else
                    CMD="$CMD -silent"
                    echo -e "${GREEN}Silent mode enabled!${NC}"
                fi
                sleep 1
                ;;
            4)
                if [[ "$CMD" == *"-v"* ]]; then
                    CMD=$(echo "$CMD" | sed 's/ -v//g')
                    echo -e "${YELLOW}Verbose mode disabled!${NC}"
                else
                    CMD="$CMD -v"
                    echo -e "${GREEN}Verbose mode enabled!${NC}"
                fi
                sleep 1
                ;;
            5)
                if [[ "$CMD" == *"-nc"* ]]; then
                    CMD=$(echo "$CMD" | sed 's/ -nc//g')
                    echo -e "${GREEN}Color output enabled!${NC}"
                else
                    CMD="$CMD -nc"
                    echo -e "${YELLOW}Color output disabled!${NC}"
                fi
                sleep 1
                ;;
            6)
                if [[ "$CMD" == *"-ei"* ]]; then
                    CMD=$(echo "$CMD" | sed 's/ -ei//g')
                    echo -e "${YELLOW}IP exclusion disabled!${NC}"
                else
                    CMD="$CMD -ei"
                    echo -e "${GREEN}IPs will be excluded from output!${NC}"
                fi
                sleep 1
                ;;
            7)
                if [[ "$CMD" == *"-cs"* ]]; then
                    CMD=$(echo "$CMD" | sed 's/ -cs//g')
                    echo -e "${YELLOW}Source collection disabled!${NC}"
                else
                    CMD="$CMD -cs"
                    echo -e "${GREEN}Sources will be collected in JSON output!${NC}"
                fi
                sleep 1
                ;;
            8)
                # Remove output-related flags
                CMD=$(echo "$CMD" | sed -E 's/ -o [^ ]*| -oD [^ ]*| -silent| -v| -nc| -ei| -cs//g')
                echo -e "${GREEN}Output options reset!${NC}"
                sleep 1
                ;;
            9)
                break
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                sleep 1
                ;;
        esac
    done
}

# Function for performance settings
performance_settings() {
    while true; do
        show_banner
        echo -e "${CYAN}=== Performance Settings ===${NC}"
        echo "Current command: ${CYAN}$CMD${NC}"
        echo ""
        echo "1) Set rate limit (requests per second)"
        echo "2) Set number of concurrent goroutines"
        echo "3) Configure provider-specific rate limits"
        echo "4) Reset performance settings"
        echo "5) Back to main menu"
        echo ""
        
        read -p "Select option: " PERF_OPTION
        
        case $PERF_OPTION in
            1)
                read -p "Enter rate limit (requests/second): " RATE_LIMIT
                if [ ! -z "$RATE_LIMIT" ]; then
                    # Remove old rate limit if exists
                    CMD=$(echo "$CMD" | sed -E 's/ -rl [^ ]*//g')
                    CMD="$CMD -rl $RATE_LIMIT"
                    echo -e "${GREEN}Rate limit set to $RATE_LIMIT!${NC}"
                fi
                sleep 1
                ;;
            2)
                read -p "Enter number of concurrent goroutines [default: 10]: " THREADS
                if [ ! -z "$THREADS" ]; then
                    # Remove old thread setting if exists
                    CMD=$(echo "$CMD" | sed -E 's/ -t [^ ]*//g')
                    CMD="$CMD -t $THREADS"
                    echo -e "${GREEN}Threads set to $THREADS!${NC}"
                fi
                sleep 1
                ;;
            3)
                read -p "Enter provider rate limits (e.g., hackertarget=10/s): " PROVIDER_RATE
                if [ ! -z "$PROVIDER_RATE" ]; then
                    # Remove old provider rate limits if exists
                    CMD=$(echo "$CMD" | sed -E 's/ -rls [^ ]*//g')
                    CMD="$CMD -rls $PROVIDER_RATE"
                    echo -e "${GREEN}Provider rate limits configured!${NC}"
                fi
                sleep 1
                ;;
            4)
                # Reset performance settings to defaults
                RATE_LIMIT=""
                THREADS="10"
                CMD=$(echo "$CMD" | sed -E 's/ -rl [^ ]*| -t [^ ]*| -rls [^ ]*//g')
                CMD="$CMD -t $THREADS"
                echo -e "${GREEN}Performance settings reset to defaults!${NC}"
                sleep 1
                ;;
            5)
                break
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                sleep 1
                ;;
        esac
    done
}

# Function for update and version
update_version() {
    show_banner
    echo -e "${PURPLE}=== Update & Version Info ===${NC}"
    echo "1) Update subfinder to latest version"
    echo "2) Show version"
    echo "3) Disable automatic update check"
    echo "4) Back to main menu"
    echo ""
    
    read -p "Select option: " UV_OPTION
    
    case $UV_OPTION in
        1)
            echo -e "${YELLOW}Updating subfinder...${NC}"
            subfinder -up
            echo -e "${GREEN}Update completed!${NC}"
            read -p "Press Enter to continue..."
            ;;
        2)
            echo -e "${GREEN}Current version:${NC}"
            subfinder -version
            read -p "Press Enter to continue..."
            ;;
        3)
            if [[ "$CMD" == *"-duc"* ]]; then
                CMD=$(echo "$CMD" | sed 's/ -duc//g')
                echo -e "${YELLOW}Automatic update check enabled!${NC}"
            else
                CMD="$CMD -duc"
                echo -e "${GREEN}Automatic update check disabled!${NC}"
            fi
            sleep 1
            ;;
        4)
            return
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            sleep 1
            ;;
    esac
}

# Function to list available sources
list_sources() {
    show_banner
    echo -e "${GREEN}=== Available Sources ===${NC}"
    subfinder -ls
    echo ""
    read -p "Press Enter to continue..."
}

# Function to show help and examples
show_help() {
    show_banner
    echo -e "${YELLOW}=== Help & Examples ===${NC}"
    echo "Basic Examples:"
    echo "  subfinder -d example.com"
    echo "  subfinder -d example.com -o results.txt"
    echo "  subfinder -dL domains.txt -oD results/"
    echo ""
    echo "Advanced Examples:"
    echo "  subfinder -d example.com -all -o results.json -json"
    echo "  subfinder -d example.com -s crtsh,github -rl 10 -t 20"
    echo "  subfinder -d example.com -active -ip -o results_with_ips.txt"
    echo ""
    echo "Configuration Files:"
    echo "  Default config: ~/.config/subfinder/config.yaml"
    echo "  Provider config: ~/.config/subfinder/provider-config.yaml"
    echo ""
    echo "Useful Tips:"
    echo "  - Use -silent for clean output (useful for piping to other tools)"
    echo "  - Combine with -json for structured data"
    echo "  - Set appropriate rate limits to avoid rate limiting"
    echo ""
    read -p "Press Enter to continue..."
}

# Main execution loop
while true; do
    show_banner
    show_main_menu
    read -r MAIN_OPTION
    
    case $MAIN_OPTION in
        1)
            single_domain
            ;;
        2)
            multiple_domains
            ;;
        3)
            advanced_options
            ;;
        4)
            source_management
            ;;
        5)
            output_config
            ;;
        6)
            performance_settings
            ;;
        7)
            update_version
            ;;
        8)
            list_sources
            ;;
        9)
            show_help
            ;;
        0)
            echo -e "${GREEN}Exiting... Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option! Please select 0-9${NC}"
            sleep 1
            ;;
    esac
done
