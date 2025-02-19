#!/bin/bash
# Usage: ./harden.sh [--debug]
# NOTE: Run this script as root.

###################### GLOBALS ######################
LOG='/var/log/ccdc/harden.log'
GITHUB_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/refs/heads/main"
pm=""
sudo_group=""
ccdc_users=( "ccdcuser1" "ccdcuser2" )
default_password="changeme"  # Fallback password for new users (if not prompted)
debug="false"
IPTABLES_BACKUP="/tmp/iptables_backup.rules"
UFW_BACKUP="/tmp/ufw_backup.rules"
#####################################################

##################### PRELIMINARY CHECKS #####################
if [ "$EUID" -ne 0 ]; then
    echo "[X] Please run this script as root (or via sudo)."
    exit 1
fi

##################### UTILITY FUNCTIONS #####################
# Prints a banner with the given text.
function print_banner {
    echo -e "\n#######################################"
    echo "#   $1"
    echo "#######################################\n"
}

# Prints debugging information if debug mode is enabled.
function debug_print {
    if [ "$debug" == "true" ]; then
        echo -n "DEBUG: "
        for arg in "$@"; do
            echo -n "$arg "
        done
        echo -e "\n"
    fi
}

# Read input (non-silent) with prompt.
function get_input_string {
    local input
    read -r -p "$1" input
    echo "$input"
}

# Read input silently with prompt.
function get_silent_input_string {
    local input
    read -r -s -p "$1" input
    echo "$input"
}

# Read multiple lines of input. User enters one per line; an empty line ends input.
function get_input_list {
    local input_list=()
    local cont="true"
    while [ "$cont" == "true" ]; do
        local input
        input=$(get_input_string "Enter input (press ENTER on a blank line to finish): ")
        if [ -z "$input" ]; then
            cont="false"
        else
            input_list+=("$input")
        fi
    done
    echo "${input_list[@]}"
}

# Append additional entries to an existing list of users.
function exclude_users {
    local users=("$@")
    local extra
    extra=$(get_input_list)
    for item in $extra; do
        users+=("$item")
    done
    echo "${users[@]}"
}

# Get list of users by filtering /etc/passwd with an awk expression and excluding given names.
function get_users {
    local awk_string="$1"
    local excludes_regex
    excludes_regex=$(sed -e 's/ /\\|/g' <<< "$2")
    local users
    users=$(awk -F ':' "$awk_string" /etc/passwd)
    local filtered
    filtered=$(echo "$users" | grep -v -e "$excludes_regex")
    readarray -t results <<< "$filtered"
    echo "${results[@]}"
}

##################### SYSTEM DETECTION & PREREQS #####################
function detect_system_info {
    print_banner "Detecting System Info"
    echo "[*] Detecting package manager..."
    if command -v apt-get &>/dev/null; then
        echo "[*] apt/apt-get detected (Debian-based)"
        pm="apt-get"
        apt-get update
    elif command -v dnf &>/dev/null; then
        echo "[*] dnf detected (Fedora-based)"
        pm="dnf"
    elif command -v zypper &>/dev/null; then
        echo "[*] zypper detected (OpenSUSE)"
        pm="zypper"
    elif command -v yum &>/dev/null; then
        echo "[*] yum detected (RHEL-based)"
        pm="yum"
    else
        echo "[X] ERROR: Could not detect package manager."
        exit 1
    fi

    echo "[*] Detecting sudo group..."
    if getent group sudo &>/dev/null; then
        sudo_group="sudo"
    elif getent group wheel &>/dev/null; then
        sudo_group="wheel"
    else
        echo "[X] ERROR: Could not detect sudo group."
        exit 1
    fi
}

function install_prereqs {
    print_banner "Installing Prerequisites"
    $pm install -y zip unzip wget curl acl
}

##################### PASSWORD & USER HELPERS #####################
# Prompt for a password twice and set it for a given user.
function prompt_and_set_password {
    local user="$1"
    local password confirm
    while true; do
        password=$(get_silent_input_string "Enter password for $user: ")
        echo
        confirm=$(get_silent_input_string "Confirm password for $user: ")
        echo
        if [ "$password" != "$confirm" ]; then
            echo "[X] Passwords do not match. Please retry."
        else
            echo "$user:$password" | chpasswd
            if [ $? -eq 0 ]; then
                echo "[*] Password for $user has been set."
            else
                echo "[X] ERROR: Failed to set password for $user."
            fi
            break
        fi
    done
}

##################### USER MANAGEMENT FUNCTIONS #####################
function change_root_password {
    print_banner "Changing Root Password"
    prompt_and_set_password "root"
}

function create_ccdc_users {
    print_banner "Creating/Updating CCDC Users"
    for user in "${ccdc_users[@]}"; do
        if id "$user" &>/dev/null; then
            echo "[*] User $user exists."
            local update_choice
            update_choice=$(get_input_string "Update password for $user? (y/N): ")
            if [[ "$update_choice" =~ ^[Yy]$ ]]; then
                prompt_and_set_password "$user"
            else
                echo "[*] Skipping password update for $user."
            fi
            # Special case for ccdcuser2: ask to change root password.
            if [ "$user" == "ccdcuser2" ]; then
                local root_choice
                root_choice=$(get_input_string "Would you like to change the root password? (y/N): ")
                if [[ "$root_choice" =~ ^[Yy]$ ]]; then
                    change_root_password
                fi
            fi
        else
            echo "[*] Creating user $user..."
            # Prefer /bin/bash if available.
            if [ -x "/bin/bash" ]; then
                useradd -m -s /bin/bash "$user"
            elif [ -x "/bin/sh" ]; then
                useradd -m -s /bin/sh "$user"
            else
                echo "[X] ERROR: Could not find a valid shell."
                exit 1
            fi

            # Set password for ccdcuser1 and ccdcuser2 interactively;
            # for any other user, use the default password.
            if [[ "$user" == "ccdcuser1" || "$user" == "ccdcuser2" ]]; then
                prompt_and_set_password "$user"
                # For ccdcuser1, add to the sudo group.
                if [ "$user" == "ccdcuser1" ]; then
                    usermod -aG "$sudo_group" "$user"
                fi
                # For ccdcuser2, offer root password change.
                if [ "$user" == "ccdcuser2" ]; then
                    local root_choice
                    root_choice=$(get_input_string "Would you like to change the root password? (y/N): ")
                    if [[ "$root_choice" =~ ^[Yy]$ ]]; then
                        change_root_password
                    fi
                fi
            else
                echo "$user:$default_password" | chpasswd && echo "[*] User $user created with default password."
            fi
        fi
        echo
    done
}

function change_passwords {
    print_banner "Changing Passwords for All Users"
    local exclusions=("root" "${ccdc_users[@]}")
    echo "[*] Excluded users: ${exclusions[*]}"
    local opt
    opt=$(get_input_string "Exclude any additional users? (y/N): ")
    if [[ "$opt" =~ ^[Yy]$ ]]; then
        exclusions=($(exclude_users "${exclusions[@]}"))
    fi

    local targets
    targets=$(get_users '$1 != "nobody" {print $1}' "${exclusions[*]}")
    echo "[*] Changing password for: $targets"
    local new_pass confirm
    while true; do
        new_pass=$(get_silent_input_string "Enter new password for target users: ")
        echo
        confirm=$(get_silent_input_string "Confirm password: ")
        echo
        if [ "$new_pass" != "$confirm" ]; then
            echo "[X] Passwords do not match. Try again."
        else
            break
        fi
    done

    for user in $targets; do
        echo "$user:$new_pass" | chpasswd && echo "[*] Password changed for $user" || echo "[X] Failed for $user"
    done
}

function disable_users {
    print_banner "Disabling User Accounts"
    local exclusions=("${ccdc_users[@]}" "root")
    echo "[*] Excluded users: ${exclusions[*]}"
    local opt
    opt=$(get_input_string "Exclude any additional users? (y/N): ")
    if [[ "$opt" =~ ^[Yy]$ ]]; then
        exclusions=($(exclude_users "${exclusions[@]}"))
    fi
    local targets
    targets=$(get_users '/\/(bash|sh|ash|zsh)$/{print $1}' "${exclusions[*]}")
    for user in $targets; do
        usermod -L "$user" && echo "[*] Account for $user locked."
        if chsh -s /usr/sbin/nologin "$user"; then
            echo "[*] Login shell for $user set to nologin."
        else
            echo "[X] Failed to set nologin for $user."
        fi
    done
}

function remove_sudoers {
    print_banner "Removing Users from Sudo Group"
    local exclusions=("ccdcuser1")
    echo "[*] Excluded from removal: ${exclusions[*]}"
    local opt
    opt=$(get_input_string "Exclude additional users? (y/N): ")
    if [[ "$opt" =~ ^[Yy]$ ]]; then
        exclusions=($(exclude_users "${exclusions[@]}"))
    fi
    local targets
    targets=$(get_users '{print $1}' "${exclusions[*]}")
    for user in $targets; do
        if id -nG "$user" | grep -qw "$sudo_group"; then
            gpasswd -d "$user" "$sudo_group" && echo "[*] Removed $user from $sudo_group."
        fi
    done
}

function audit_running_services {
    print_banner "Auditing Running Services (Listening Ports)"
    ss -tuln
}

##################### FIREWALL & IPTABLES FUNCTIONS #####################
function disable_other_firewalls {
    print_banner "Disabling Other Firewalls"
    if command -v firewalld &>/dev/null; then
        echo "[*] Disabling firewalld..."
        systemctl stop firewalld
        systemctl disable firewalld
    fi
}

function backup_current_iptables_rules {
    # Save rules persistently based on OS.
    if grep -qi 'fedora\|centos\|rhel' /etc/os-release; then
        iptables-save > /etc/sysconfig/iptables && echo "[*] Iptables saved to /etc/sysconfig/iptables"
    elif grep -qi 'debian\|ubuntu' /etc/os-release; then
        if [ -f /etc/iptables/rules.v4 ]; then
            iptables-save > /etc/iptables/rules.v4 && echo "[*] Iptables saved to /etc/iptables/rules.v4"
        elif command -v netfilter-persistent &>/dev/null; then
            netfilter-persistent save && echo "[*] Iptables saved via netfilter-persistent"
        else
            echo "[!] Warning: Iptables persistent saving not configured."
        fi
    else
        echo "[*] Unknown OS. Save iptables manually if needed."
    fi
    iptables-save > "$IPTABLES_BACKUP"
}

function restore_iptables_rules {
    if [ -f "$IPTABLES_BACKUP" ]; then
        iptables-restore < "$IPTABLES_BACKUP" && echo "[*] Iptables rules restored."
    else
        echo "[X] No iptables backup found."
    fi
}

function backup_current_ufw_rules {
    if [ -f /etc/ufw/user.rules ]; then
        cp /etc/ufw/user.rules "$UFW_BACKUP" && echo "[*] UFW rules backed up to $UFW_BACKUP"
    else
        echo "[X] UFW rules file not found."
    fi
}

function restore_ufw_rules {
    if [ -f "$UFW_BACKUP" ]; then
        ufw reset
        cp "$UFW_BACKUP" /etc/ufw/user.rules
        ufw reload
        echo "[*] UFW rules restored."
    else
        echo "[X] No UFW backup found."
    fi
}

function setup_ufw {
    print_banner "Configuring UFW"
    $pm install -y ufw
    sed -i 's/^IPV6=yes/IPV6=no/' /etc/default/ufw
    ufw --force disable
    ufw --force reset
    ufw default deny outgoing
    ufw default deny incoming
    ufw allow out on lo
    ufw allow out to any port 53 proto tcp
    ufw allow out to any port 53 proto udp
    echo "[*] UFW configured with strict outbound deny (DNS allowed)."
    echo "Enter additional incoming ports to open (one per line):"
    local ports
    ports=$(get_input_list)
    for port in $ports; do
        ufw allow "$port" && echo "[*] Allowed port $port"
    done
    ufw logging on
    ufw --force enable
    backup_current_ufw_rules
}

function ufw_disable_default_deny {
    print_banner "Temporarily Allow Outbound (UFW)"
    ufw default allow outgoing
    backup_current_ufw_rules
}

function ufw_enable_default_deny {
    print_banner "Reverting Outbound Policy (UFW)"
    ufw default deny outgoing
    ufw allow out on lo
    ufw allow out to any port 53 proto tcp
    ufw allow out to any port 53 proto udp
    backup_current_ufw_rules
}

function reset_iptables {
    print_banner "Resetting IPTables"
    iptables -F
    iptables -X
    iptables -Z
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    backup_current_iptables_rules
    echo "[*] IPTables reset."
}

function setup_custom_iptables {
    print_banner "Configuring Custom IPTables"
    reset_iptables
    iptables -P OUTPUT DROP
    iptables -P INPUT DROP
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

    echo "Select DNS option:"
    echo "  1) Cloudflare (1.1.1.1, 1.0.0.1)"
    echo "  2) Use default gateway"
    echo "  3) Use default DNS (192.168.XXX.1, 192.168.XXX.2)"
    local dns_choice
    dns_choice=$(get_input_string "Choice [1-3]: ")
    local dns_value
    if [ "$dns_choice" == "1" ]; then
        dns_value="1.1.1.1 1.0.0.1"
    elif [ "$dns_choice" == "2" ]; then
        local default_gateway
        default_gateway=$(ip route | awk '/default/ {print $3; exit}')
        if [ -z "$default_gateway" ]; then
            echo "[X] Default gateway not found. Falling back."
            dns_value="192.168.XXX.1 192.168.XXX.2"
        else
            dns_value="$default_gateway"
        fi
    else
        dns_value="192.168.XXX.1 192.168.XXX.2"
    fi

    backup_current_iptables_rules
    local ext_choice
    ext_choice=$(get_input_string "Add additional iptables rules? (y/N): ")
    if [[ "$ext_choice" =~ ^[Yy]$ ]]; then
        extended_iptables
    fi
}

function custom_iptables_manual_rules {
    print_banner "Add Manual Inbound IPTables Rule"
    local ports
    ports=$(get_input_list)
    for port in $ports; do
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT && echo "[*] Allowed inbound port $port"
        backup_current_iptables_rules
    done
}

function custom_iptables_manual_outbound_rules {
    print_banner "Add Manual Outbound IPTables Rule"
    local ports
    ports=$(get_input_list)
    for port in $ports; do
        iptables -A OUTPUT -p tcp --dport "$port" -j ACCEPT && echo "[*] Allowed outbound port $port"
        backup_current_iptables_rules
    done
}

function iptables_disable_default_deny {
    print_banner "Temporarily Allow All (IPTables)"
    backup_current_iptables_rules
    iptables -P OUTPUT ACCEPT
    iptables -P INPUT ACCEPT
    echo "[*] IPTables policies set to ACCEPT."
}

function iptables_enable_default_deny {
    print_banner "Reapplying Default Deny (IPTables)"
    backup_current_iptables_rules
    iptables -P OUTPUT DROP
    iptables -P INPUT DROP
    echo "[*] IPTables policies set to DROP."
}

function extended_iptables {
    while true; do
        print_banner "Extended IPTables Management"
        echo " 1) Add Outbound ACCEPT rule"
        echo " 2) Add Inbound ACCEPT rule"
        echo " 3) Add Outbound DROP rule"
        echo " 4) Add Inbound DROP rule"
        echo " 5) Show all rules"
        echo " 6) Reset firewall"
        echo " 7) Exit extended management"
        local choice
        read -p "Enter your choice [1-7]: " choice
        case $choice in
            1)
                read -p "Enter outbound port number: " port
                iptables -A OUTPUT -p tcp --dport "$port" -j ACCEPT && echo "[*] Added outbound ACCEPT rule for port $port"
                backup_current_iptables_rules
                ;;
            2)
                read -p "Enter inbound port number: " port
                iptables -A INPUT -p tcp --dport "$port" -j ACCEPT && echo "[*] Added inbound ACCEPT rule for port $port"
                backup_current_iptables_rules
                ;;
            3)
                read -p "Enter outbound port number to DROP: " port
                iptables -A OUTPUT -p tcp --dport "$port" -j DROP && echo "[*] Added outbound DROP rule for port $port"
                backup_current_iptables_rules
                ;;
            4)
                read -p "Enter inbound port number to DROP: " port
                iptables -A INPUT -p tcp --dport "$port" -j DROP && echo "[*] Added inbound DROP rule for port $port"
                backup_current_iptables_rules
                ;;
            5)
                iptables -L -n -v
                ;;
            6)
                reset_iptables
                backup_current_iptables_rules
                ;;
            7)
                echo "[*] Exiting extended IPTables management."
                break
                ;;
            *)
                echo "[X] Invalid option."
                ;;
        esac
        echo
    done
}

function firewall_configuration_menu {
    detect_system_info
    install_prereqs
    disable_other_firewalls
    audit_running_services
    read -p "Press ENTER to continue to firewall configuration..." dummy

    print_banner "Firewall Configuration Menu"
    echo "Select firewall type:"
    echo " 1) UFW"
    echo " 2) IPTables"
    local fw_type
    read -p "Enter your choice [1-2]: " fw_type
    echo
    case $fw_type in
        1)
            while true; do
                print_banner "UFW Menu"
                echo " 1) Setup UFW"
                echo " 2) Add inbound allow rule"
                echo " 3) Add outbound allow rule"
                echo " 4) Show UFW rules"
                echo " 5) Reset UFW"
                echo " 6) Show running services"
                echo " 7) Temporarily allow outbound (disable default deny)"
                echo " 8) Reinstate default deny for outbound"
                echo " 9) Exit UFW menu"
                local ufw_choice
                read -p "Enter your choice [1-9]: " ufw_choice
                echo
                case $ufw_choice in
                    1) setup_ufw ;;
                    2)
                        echo "Enter inbound ports to allow:"
                        local ports; ports=$(get_input_list)
                        for port in $ports; do
                            ufw allow in "$port" && echo "[*] Allowed inbound port $port"
                        done
                        ;;
                    3)
                        echo "Enter outbound ports to allow:"
                        local ports; ports=$(get_input_list)
                        for port in $ports; do
                            ufw allow out "$port" && echo "[*] Allowed outbound port $port"
                        done
                        ;;
                    4) ufw status numbered ;;
                    5) ufw --force reset && echo "[*] UFW reset." ;;
                    6) audit_running_services ;;
                    7) ufw_disable_default_deny ;;
                    8) ufw_enable_default_deny ;;
                    9) break ;;
                    *) echo "[X] Invalid option." ;;
                esac
                echo
            done
            ;;
        2)
            while true; do
                print_banner "IPTables Menu"
                echo " 1) Setup IPTables"
                echo " 2) Add outbound allow rule"
                echo " 3) Add inbound allow rule"
                echo " 4) Add outbound deny rule"
                echo " 5) Add inbound deny rule"
                echo " 6) Show IPTables rules"
                echo " 7) Reset IPTables"
                echo " 8) Show running services"
                echo " 9) Temporarily allow all (disable default deny)"
                echo " 10) Reinstate default deny"
                echo " 11) Exit IPTables menu"
                local ipt_choice
                read -p "Enter your choice [1-11]: " ipt_choice
                echo
                case $ipt_choice in
                    1) setup_custom_iptables ;;
                    2) custom_iptables_manual_outbound_rules ;;
                    3) custom_iptables_manual_rules ;;
                    4)
                        read -p "Enter outbound port to deny: " port
                        iptables -A OUTPUT -p tcp --dport "$port" -j DROP && echo "[*] Denied outbound port $port"
                        backup_current_iptables_rules
                        ;;
                    5)
                        read -p "Enter inbound port to deny: " port
                        iptables -A INPUT -p tcp --dport "$port" -j DROP && echo "[*] Denied inbound port $port"
                        backup_current_iptables_rules
                        ;;
                    6) iptables -L -n -v ;;
                    7) reset_iptables ;;
                    8) audit_running_services ;;
                    9) iptables_disable_default_deny ;;
                    10) iptables_enable_default_deny ;;
                    11) break ;;
                    *) echo "[X] Invalid option." ;;
                esac
                echo
            done
            ;;
        *)
            echo "[X] Invalid firewall selection."
            ;;
    esac
}

##################### BACKUP FUNCTIONS #####################
function backup_directories {
    print_banner "Backup Directories"
    local default_dirs=( "/etc/nginx" "/etc/apache2" "/usr/share/nginx" "/var/www" "/var/www/html" "/etc/lighttpd" "/etc/mysql" "/etc/postgresql" "/var/lib/apache2" "/var/lib/mysql" "/etc/redis" "/etc/phpMyAdmin" "/etc/php.d" )
    local detected_dirs=()
    echo "[*] Scanning for critical directories..."
    for d in "${default_dirs[@]}"; do
        if [ -d "$d" ]; then
            detected_dirs+=("$d")
        fi
    done

    local backup_list=()
    if [ ${#detected_dirs[@]} -gt 0 ]; then
        echo "[*] Detected directories:"
        for d in "${detected_dirs[@]}"; do
            echo "   $d"
        done
        local detected_choice
        detected_choice=$(get_input_string "Back these up? (y/N): ")
        if [[ "$detected_choice" =~ ^[Yy]$ ]]; then
            backup_list=("${detected_dirs[@]}")
        fi
    else
        echo "[*] No critical directories detected."
    fi

    local additional_choice
    additional_choice=$(get_input_string "Backup any additional files/directories? (y/N): ")
    if [[ "$additional_choice" =~ ^[Yy]$ ]]; then
        echo "[*] Enter additional paths (one per line):"
        local additional_dirs; additional_dirs=$(get_input_list)
        for item in $additional_dirs; do
            local path
            path=$(readlink -f "$item")
            if [ -e "$path" ]; then
                backup_list+=("$path")
            else
                echo "[X] $path does not exist."
            fi
        done
    fi

    if [ ${#backup_list[@]} -eq 0 ]; then
        echo "[*] No items selected for backup. Exiting backup."
        return
    fi

    local backup_name
    while true; do
        backup_name=$(get_input_string "Enter backup archive name (without .zip): ")
        if [ -n "$backup_name" ]; then
            [[ "$backup_name" != *.zip ]] && backup_name="${backup_name}.zip"
            break
        fi
        echo "[X] Backup name cannot be blank."
    done

    echo "[*] Creating archive..."
    zip -r "$backup_name" "${backup_list[@]}" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "[X] Archive creation failed."
        return
    fi
    echo "[*] Archive created: $backup_name"

    echo "[*] Encrypting archive."
    local enc_password enc_confirm
    while true; do
        enc_password=$(get_silent_input_string "Enter encryption password: ")
        echo
        enc_confirm=$(get_silent_input_string "Confirm encryption password: ")
        echo
        if [ "$enc_password" != "$enc_confirm" ]; then
            echo "[X] Passwords do not match. Retry."
        else
            break
        fi
    done

    local enc_archive="${backup_name}.enc"
    openssl enc -aes-256-cbc -salt -in "$backup_name" -out "$enc_archive" -k "$enc_password"
    if [ $? -ne 0 ]; then
        echo "[X] Encryption failed."
        return
    fi
    echo "[*] Encrypted archive created: $enc_archive"

    local storage_dir
    while true; do
        storage_dir=$(get_input_string "Enter directory to store encrypted backup: ")
        storage_dir=$(readlink -f "$storage_dir")
        if [ -d "$storage_dir" ]; then
            break
        else
            echo "[*] Directory does not exist. Creating..."
            mkdir -p "$storage_dir" && break || echo "[X] Failed to create directory."
        fi
    done

    mv "$enc_archive" "$storage_dir/" && echo "[*] Encrypted archive moved to $storage_dir"
    rm -f "$backup_name"
    echo "[*] Backup complete."
}

function unencrypt_backups {
    print_banner "Decrypt Backup"
    local encrypted_file
    while true; do
        encrypted_file=$(get_input_string "Enter path to encrypted backup: ")
        encrypted_file=$(readlink -f "$encrypted_file")
        if [ ! -f "$encrypted_file" ]; then
            echo "[X] File not found. Please try again."
        else
            break
        fi
    done

    local dec_password dec_confirm
    while true; do
        dec_password=$(get_silent_input_string "Enter decryption password: ")
        echo
        dec_confirm=$(get_silent_input_string "Confirm decryption password: ")
        echo
        if [ "$dec_password" != "$dec_confirm" ]; then
            echo "[X] Passwords do not match."
        else
            break
        fi
    done

    local temp_output="decrypted_backup.zip"
    openssl enc -d -aes-256-cbc -in "$encrypted_file" -out "$temp_output" -k "$dec_password"
    if [ $? -ne 0 ]; then
        echo "[X] Decryption failed. Check password."
        rm -f "$temp_output"
        return
    fi

    echo "[*] Decryption successful: $temp_output"
    local extract_choice
    extract_choice=$(get_input_string "Extract the archive? (y/N): ")
    if [[ "$extract_choice" =~ ^[Yy]$ ]]; then
        local extract_dir
        extract_dir=$(get_input_string "Enter extraction directory: ")
        extract_dir=$(readlink -f "$extract_dir")
        mkdir -p "$extract_dir"
        unzip "$temp_output" -d "$extract_dir"
        echo "[*] Archive extracted to $extract_dir"
        rm -f "$temp_output"
    else
        echo "[*] Decrypted archive remains as $temp_output"
    fi
}

function backups {
    print_banner "Backup Menu"
    echo " 1) Backup Directories"
    echo " 2) Decrypt Backup"
    echo " 3) Exit Backup Menu"
    local backup_choice
    read -p "Enter your choice [1-3]: " backup_choice
    case $backup_choice in
        1) backup_directories ;;
        2) unencrypt_backups ;;
        3) echo "[*] Exiting Backup Menu." ;;
        *) echo "[X] Invalid option." ;;
    esac
}

##################### SPLUNK & WEB HARDENING FUNCTIONS #####################
function setup_splunk {
    print_banner "Installing Splunk"
    local indexer_ip
    indexer_ip=$(get_input_string "Enter Splunk forwarder server IP: ")
    wget "$GITHUB_URL/splunk/splunk.sh" --no-check-certificate
    chmod +x splunk.sh
    ./splunk.sh -f "$indexer_ip"
}

function backup_databases {
    print_banner "Backing Up Databases (MySQL/MariaDB)"
    if service mysql status &>/dev/null; then
        echo "[+] MySQL/MariaDB is active."
        mysql -u root -e "quit" &>/dev/null
        if [ $? -eq 0 ]; then
            echo "[!] Empty root password detected. Backing up databases..."
            mysqldump --all-databases > backup.sql
            local ns pass
            ns=$(date +%N)
            pass=$(echo "${ns}$RANDOM" | sha256sum | cut -d" " -f1)
            echo "[+] Backup complete. Key for dump: $pass"
            gpg -c --pinentry-mode=loopback --passphrase "$pass" backup.sql
            rm backup.sql
        fi
    fi

    if service postgresql status &>/dev/null; then
        echo "[+] PostgreSQL is active."
    fi
}

function secure_php_ini {
    print_banner "Securing PHP Configuration"
    local ini
    for ini in $(find / -name "php.ini" 2>/dev/null); do
        echo "[+] Updating $ini"
        cat <<EOF >> "$ini"
disable_functions = shell_exec, exec, passthru, proc_open, popen, system, phpinfo
max_execution_time = 3
register_globals = off
magic_quotes_gpc = on
allow_url_fopen = off
allow_url_include = off
display_errors = off
short_open_tag = off
session.cookie_httponly = 1
session.use_only_cookies = 1
session.cookie_secure = 1
EOF
    done
}

function secure_ssh {
    print_banner "Securing SSH"
    local service_name config_file
    if service sshd status &>/dev/null; then
        service_name="sshd"
    elif service ssh status &>/dev/null; then
        service_name="ssh"
    else
        echo "[*] SSH service not found. Skipping SSH hardening."
        return
    fi

    config_file="/etc/ssh/sshd_config"
    if [ ! -f "$config_file" ]; then
        echo "[X] ERROR: SSH configuration file not found: $config_file"
        return
    fi

    # Recommended hardening: disable root login and require key authentication.
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$config_file"
    sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$config_file"
    sed -i 's/^#*UseDNS.*/UseDNS no/' "$config_file"
    sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$config_file"
    sed -i 's/^#*AddressFamily.*/AddressFamily inet/' "$config_file"
    sed -i 's/^#*Banner.*/Banner none/' "$config_file"

    if sshd -t; then
        if command -v systemctl &>/dev/null; then
            systemctl restart "$service_name"
        else
            service "$service_name" restart
        fi
        echo "[*] SSH hardening applied and $service_name restarted."
    else
        echo "[X] ERROR: SSH configuration test failed."
    fi
}

function install_modsecurity {
    print_banner "Installing ModSecurity"
    # Temporarily allow outbound traffic for package installation.
    iptables -P OUTPUT ACCEPT
    if command -v yum &>/dev/null; then
        echo "ModSecurity installation for RHEL-based systems not implemented."
    elif command -v apt-get &>/dev/null; then
        apt-get update
        apt-get -y install libapache2-mod-security2
        a2enmod security2
        cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
        sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/g' /etc/modsecurity/modsecurity.conf
        systemctl restart apache2
    elif command -v apk &>/dev/null; then
        echo "Alpine-based ModSecurity installation not implemented."
    else
        echo "Unsupported distribution for ModSecurity installation."
        exit 1
    fi
    iptables -P OUTPUT DROP
}

function remove_profiles {
    print_banner "Removing Profile Files"
    mv /etc/profile.d /etc/profile.d.bak 2>/dev/null
    mv /etc/profile /etc/profile.bak 2>/dev/null
    for f in ".profile" ".bashrc" ".bash_login"; do
        find /home /root \( -path "/root/*" -o -path "/home/ccdcuser1/*" -o -path "/home/ccdcuser2/*" \) -prune -o -name "$f" -exec rm {} \;
    done
}

function fix_pam {
    print_banner "Fixing PAM Configuration"
    iptables -P OUTPUT ACCEPT
    if command -v yum &>/dev/null; then
        if command -v authconfig &>/dev/null; then
            authconfig --updateall
            yum -y reinstall pam
        else
            echo "No authconfig found. Cannot fix PAM."
        fi
    elif command -v apt-get &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive pam-auth-update --force
        apt-get -y --reinstall install libpam-runtime libpam-modules
    elif command -v apk &>/dev/null; then
        if [ -d /etc/pam.d ]; then
            apk fix --purge linux-pam
            for file in $(find /etc/pam.d -name "*.apk-new" 2>/dev/null); do
                mv "$file" "${file%.apk-new}"
            done
        else
            echo "PAM not installed."
        fi
    elif command -v pacman &>/dev/null; then
        mv /etc/pam.d /etc/pam.d.backup
        cp -R "$BACKUPDIR" /etc/pam.d
        pacman -S pam --noconfirm
    else
        echo "Unknown OS; PAM fix not applied."
    fi
    iptables -P OUTPUT DROP
}

function search_ssn {
    print_banner "Searching for SSN Patterns"
    local rootdir="/home/"
    local ssn_pattern='[0-9]\{3\}-[0-9]\{2\}-[0-9]\{4\}'
    find "$rootdir" -type f \( -name "*.txt" -o -name "*.csv" \) -exec sh -c '
        for file do
            grep -Hn "$0" "$file" | while read -r line; do
                echo "$file:SSN:$line"
            done
        done
    ' "$ssn_pattern" {} +
}

function remove_unused_packages {
    print_banner "Removing Unused Packages"
    if command -v yum &>/dev/null; then
        yum purge -y -q netcat nc gcc cmake make telnet
    elif command -v apt-get &>/dev/null; then
        apt-get -y purge netcat nc gcc cmake make telnet
    elif command -v apk &>/dev/null; then
        apk remove gcc make
    else
        echo "Unsupported package manager for removal."
    fi
}

function patch_vulnerabilities {
    print_banner "Patching Vulnerabilities"
    chmod 0755 /usr/bin/pkexec
    sysctl -w kernel.unprivileged_userns_clone=0
    echo "kernel.unprivileged_userns_clone = 0" >> /etc/sysctl.conf
    sysctl -p >/dev/null
}

function check_permissions {
    print_banner "Checking and Setting Critical Permissions"
    chown root:root /etc/shadow /etc/passwd
    chmod 640 /etc/shadow
    chmod 644 /etc/passwd
    echo "[+] SUID binaries:"
    find / -perm -4000 2>/dev/null
    echo "[+] Directories with 777 permissions (max depth 3):"
    find / -maxdepth 3 -type d -perm -777 2>/dev/null
    echo "[+] Files with capabilities:"
    getcap -r / 2>/dev/null
    echo "[+] Files with extended ACLs in critical directories:"
    getfacl -R /etc/ /usr/ /root/
}

function sysctl_config {
    print_banner "Applying sysctl Configurations"
    local file="/etc/sysctl.conf"
    cat <<EOF >> "$file"
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_challenge_ack_limit = 1000000
net.ipv4.tcp_rfc1337 = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.icmp_echo_ignore_all = 1
kernel.core_uses_pid = 1
kernel.kptr_restrict = 2
kernel.perf_event_paranoid = 2
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.yama.ptrace_scope = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.unprivileged_userns_clone = 0
fs.protected_fifos = 2
fs.protected_regular = 2
EOF
    sysctl -p >/dev/null
}

function my_secure_sql_installation {
    print_banner "Running mysql_secure_installation"
    local sql_choice
    sql_choice=$(get_input_string "Run mysql_secure_installation? (y/N): ")
    if [[ "$sql_choice" =~ ^[Yy]$ ]]; then
        mysql_secure_installation
    else
        echo "[*] Skipping mysql_secure_installation."
    fi
}

function manage_web_immutability {
    print_banner "Manage Web Directory Immutability"
    local default_web_dirs=( "/etc/nginx" "/etc/apache2" "/usr/share/nginx" "/var/www" "/var/www/html" "/etc/lighttpd" "/etc/mysql" "/etc/postgresql" "/var/lib/apache2" "/var/lib/mysql" "/etc/redis" "/etc/phpMyAdmin" "/etc/php.d" )
    local detected_web_dirs=()
    for dir in "${default_web_dirs[@]}"; do
        [ -d "$dir" ] && detected_web_dirs+=("$dir")
    done

    if [ ${#detected_web_dirs[@]} -eq 0 ]; then
        echo "[*] No critical web directories found."
        return
    fi

    echo "[*] Detected web directories:"
    for d in "${detected_web_dirs[@]}"; do
        echo "    $d"
    done

    local imm_choice
    imm_choice=$(get_input_string "Set these directories to immutable? (y/N): ")
    if [[ "$imm_choice" =~ ^[Yy]$ ]]; then
        for d in "${detected_web_dirs[@]}"; do
            chattr +i "$d" && echo "[*] Immutable flag set on $d"
        done
    else
        local unimm_choice
        unimm_choice=$(get_input_string "Remove immutable flag from these directories? (y/N): ")
        if [[ "$unimm_choice" =~ ^[Yy]$ ]]; then
            for d in "${detected_web_dirs[@]}"; do
                chattr -i "$d" && echo "[*] Immutable flag removed from $d"
            done
        else
            echo "[*] No changes made."
        fi
    fi
}

function harden_web {
    print_banner "Web Hardening Initiated"
    backup_databases
    secure_php_ini
    install_modsecurity
    my_secure_sql_installation
    manage_web_immutability
}

##################### ADVANCED HARDENING FUNCTIONS #####################
function setup_iptables_cronjob {
    print_banner "Setting Up IPTables Persistence Cronjob"
    local cron_file
    if grep -qi 'fedora\|centos\|rhel' /etc/os-release; then
        cron_file="/etc/cron.d/iptables_persistence"
        cat > "$cron_file" <<EOF
*/5 * * * * root iptables-save > /etc/sysconfig/iptables
EOF
        echo "[*] Cron job created at $cron_file."
    elif grep -qi 'debian\|ubuntu' /etc/os-release; then
        cron_file="/etc/cron.d/iptables_persistence"
        cat > "$cron_file" <<EOF
*/5 * * * * root iptables-save > /etc/iptables/rules.v4
EOF
        echo "[*] Cron job created at $cron_file."
    else
        echo "[*] Unknown OS. Please set up iptables persistence manually."
    fi
}

function disable_unnecessary_services {
    print_banner "Disabling Unnecessary Services"
    local disable_sshd
    disable_sshd=$(get_input_string "Disable SSHD? (WARNING: may lock you out) (y/N): ")
    if [[ "$disable_sshd" =~ ^[Yy]$ ]]; then
        if systemctl is-active sshd &>/dev/null; then
            systemctl stop sshd
            systemctl disable sshd
            echo "[*] SSHD disabled."
        else
            echo "[*] SSHD not active."
        fi
    fi
    local disable_cockpit
    disable_cockpit=$(get_input_string "Disable Cockpit? (y/N): ")
    if [[ "$disable_cockpit" =~ ^[Yy]$ ]]; then
        if systemctl is-active cockpit &>/dev/null; then
            systemctl stop cockpit
            systemctl disable cockpit
            echo "[*] Cockpit disabled."
        else
            echo "[*] Cockpit not active."
        fi
    fi
}

function setup_firewall_maintenance_cronjob_iptables {
    print_banner "Setting Up IPTables Maintenance Cronjob"
    local script_file="/usr/local/sbin/firewall_maintain.sh"
    cat > "$script_file" <<'EOF'
#!/bin/bash
open_ports=$(ss -lnt | awk 'NR>1 {print $4}' | awk -F':' '{print $NF}' | sort -u)
for port in $open_ports; do
    iptables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport $port -j ACCEPT
done
EOF
    chmod +x "$script_file"
    local cron_file="/etc/cron.d/firewall_maintenance"
    cat > "$cron_file" <<EOF
*/5 * * * * root $script_file
EOF
    echo "[*] IPTables maintenance cron job created."
}

function setup_firewall_maintenance_cronjob_ufw {
    print_banner "Setting Up UFW Maintenance Cronjob"
    backup_current_ufw_rules
    local script_file="/usr/local/sbin/ufw_maintain.sh"
    cat > "$script_file" <<'EOF'
#!/bin/bash
if [ -f /tmp/ufw_backup.rules ]; then
    ufw reset
    cp /tmp/ufw_backup.rules /etc/ufw/user.rules
    ufw reload
fi
EOF
    chmod +x "$script_file"
    local cron_file="/etc/cron.d/ufw_maintenance"
    cat > "$cron_file" <<EOF
*/5 * * * * root $script_file
EOF
    echo "[*] UFW maintenance cron job created."
}

function setup_firewall_maintenance_cronjob {
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        setup_firewall_maintenance_cronjob_ufw
    else
        setup_firewall_maintenance_cronjob_iptables
    fi
}

function setup_nat_clear_cronjob {
    print_banner "Setting Up NAT Table Clear Cronjob"
    local cron_file="/etc/cron.d/clear_nat_table"
    cat > "$cron_file" <<EOF
*/5 * * * * root iptables -t nat -F
EOF
    echo "[*] NAT clear cron job created."
}

function setup_service_restart_cronjob {
    print_banner "Setting Up Service Restart Cronjob"
    local detected_service=""
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        detected_service="ufw"
    elif systemctl is-active firewalld &>/dev/null; then
        detected_service="firewalld"
    elif systemctl is-active netfilter-persistent &>/dev/null; then
        detected_service="netfilter-persistent"
    else
        echo "[*] No recognized firewall service detected."
    fi

    if [ -n "$detected_service" ]; then
        local script_file="/usr/local/sbin/restart_${detected_service}.sh"
        cat > "$script_file" <<EOF
#!/bin/bash
systemctl restart $detected_service
EOF
        chmod +x "$script_file"
        local cron_file="/etc/cron.d/restart_${detected_service}"
        cat > "$cron_file" <<EOF
*/5 * * * * root $script_file
EOF
        echo "[*] Cron job created to restart $detected_service every 5 minutes."
    fi

    local add_extra
    add_extra=$(get_input_string "Add additional services to restart via cron? (y/N): ")
    if [[ "$add_extra" =~ ^[Yy]$ ]]; then
        while true; do
            local extra_service
            extra_service=$(get_input_string "Enter additional service name (or blank to finish): ")
            [ -z "$extra_service" ] && break
            local extra_script="/usr/local/sbin/restart_${extra_service}.sh"
            cat > "$extra_script" <<EOF
#!/bin/bash
systemctl restart $extra_service
EOF
            chmod +x "$extra_script"
            local extra_cron="/etc/cron.d/restart_${extra_service}"
            cat > "$extra_cron" <<EOF
*/5 * * * * root $extra_script
EOF
            echo "[*] Cron job created to restart $extra_service every 5 minutes."
        done
    fi
}

function reset_advanced_hardening {
    print_banner "Resetting Advanced Hardening Configurations"
    rm -f /etc/cron.d/iptables_persistence
    rm -f /etc/cron.d/firewall_maintenance /usr/local/sbin/firewall_maintain.sh
    rm -f /etc/cron.d/clear_nat_table
    rm -f /etc/cron.d/restart_* /usr/local/sbin/restart_*
    echo "[*] Advanced hardening configurations reset."
}

function run_full_advanced_hardening {
    print_banner "Running Full Advanced Hardening Process"
    setup_iptables_cronjob
    disable_unnecessary_services
    setup_firewall_maintenance_cronjob
    setup_nat_clear_cronjob
    setup_service_restart_cronjob
    echo "[*] Advanced hardening process completed."
}

function advanced_hardening {
    while true; do
        print_banner "Advanced Hardening Menu"
        echo " 1) Run full advanced hardening process"
        echo " 2) Set up IPTables persistence cronjob"
        echo " 3) Disable SSHD/Cockpit services"
        echo " 4) Set up firewall maintenance cronjob"
        echo " 5) Set up NAT table clear cronjob"
        echo " 6) Set up service restart cronjob"
        echo " 7) Reset advanced hardening configurations"
        echo " 8) Exit advanced hardening menu"
        local adv_choice
        read -p "Enter your choice [1-8]: " adv_choice
        case $adv_choice in
            1) run_full_advanced_hardening ;;
            2) setup_iptables_cronjob ;;
            3) disable_unnecessary_services ;;
            4) setup_firewall_maintenance_cronjob ;;
            5) setup_nat_clear_cronjob ;;
            6) setup_service_restart_cronjob ;;
            7) reset_advanced_hardening ;;
            8) echo "[*] Exiting advanced hardening menu."; break ;;
            *) echo "[X] Invalid option." ;;
        esac
        echo
    done
}

function show_web_hardening_menu {
    print_banner "Web Hardening Menu"
    echo " 1) Run full web hardening process"
    echo " 2) Backup databases"
    echo " 3) Secure PHP configuration"
    echo " 4) Install ModSecurity"
    echo " 5) Run mysql_secure_installation"
    echo " 6) Manage web directory immutability"
    echo " 7) Exit Web Hardening Menu"
    local web_choice
    read -p "Enter your choice [1-7]: " web_choice
    case $web_choice in
        1)
            harden_web
            ;;
        2)
            backup_databases
            ;;
        3)
            secure_php_ini
            ;;
        4)
            install_modsecurity
            ;;
        5)
            my_secure_sql_installation
            ;;
        6)
            manage_web_immutability
            ;;
        7)
            echo "[*] Exiting Web Hardening Menu"
            ;;
        *)
            echo "[X] Invalid option."
            ;;
    esac
}

##################### MAIN MENU FUNCTIONS #####################
function show_menu {
    print_banner "Hardening Script Main Menu"
    echo " 1) Full Hardening Process (Run all)"
    echo " 2) User Management"
    echo " 3) Firewall Configuration"
    echo " 4) Backup"
    echo " 5) Splunk Installation"
    echo " 6) SSH Hardening"
    echo " 7) PAM/Profile Fixes & System Config"
    echo " 8) Web Hardening"
    echo " 9) Advanced Hardening"
    echo " 10) Exit"
    local menu_choice
    read -p "Enter your choice [1-10]: " menu_choice
    echo
    case $menu_choice in
        1) main ;;
        2)
            detect_system_info
            install_prereqs
            create_ccdc_users
            change_passwords
            disable_users
            remove_sudoers
            ;;
        3) firewall_configuration_menu ;;
        4) backups ;;
        5) setup_splunk ;;
        6) secure_ssh ;;
        7)
            fix_pam
            remove_profiles
            check_permissions
            sysctl_config
            ;;
        8) show_web_hardening_menu ;;
        9) advanced_hardening ;;
        10) echo "Exiting..."; exit 0 ;;
        *) echo "[X] Invalid option. Exiting."; exit 1 ;;
    esac
}

function main {
    echo "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    echo "[*] Starting full hardening process"
    detect_system_info
    install_prereqs
    create_ccdc_users
    change_passwords
    disable_users
    remove_sudoers
    audit_running_services
    disable_other_firewalls
    firewall_configuration_menu
    backups
    setup_splunk
    secure_ssh
    remove_profiles
    fix_pam
    search_ssn
    remove_unused_packages
    patch_vulnerabilities
    check_permissions
    sysctl_config
    local web_choice
    web_choice=$(get_input_string "Perform web hardening? (y/N): ")
    if [[ "$web_choice" =~ ^[Yy]$ ]]; then
        show_web_hardening_menu
    fi
    local adv_choice
    adv_choice=$(get_input_string "Perform advanced hardening? (y/N): ")
    if [[ "$adv_choice" =~ ^[Yy]$ ]]; then
        advanced_hardening
    fi
    echo "[*] Full hardening process complete."
    echo "[*] See log at $LOG"
    echo "[*] ***Please install system updates now***"
}

##################### ARGUMENT PARSING & LOGGING SETUP #####################
for arg in "$@"; do
    case "$arg" in
        --debug )
            debug="true"
            echo "[*] Debug mode enabled"
            ;;
    esac
done

LOG_PATH=$(dirname "$LOG")
if [ ! -d "$LOG_PATH" ]; then
    mkdir -p "$LOG_PATH"
    chown root:root "$LOG_PATH"
    chmod 750 "$LOG_PATH"
fi

##################### MAIN EXECUTION #####################
show_menu
