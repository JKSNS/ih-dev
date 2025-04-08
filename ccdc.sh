#!/bin/bash
# Usage: ./harden.sh [option]
#    e.g.: ./harden.sh -ansible
#
# NOTE: It is recommended to run this script with root privileges (e.g., via sudo)
if [ "$EUID" -ne 0 ]; then
    echo "[X] Please run this script as root (or via sudo)."
    exit 1
fi

###################### GLOBALS ######################
LOG='/var/log/ccdc/harden.log'
GITHUB_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/refs/heads/main"
pm=""
sudo_group=""
ccdc_users=( "ccdcuser1" "ccdcuser2" )
debug="false"
ANSIBLE="false"      # When set to "true", interactive prompts will be skipped.
IPTABLES_BACKUP="/tmp/iptables_backup.rules"
UFW_BACKUP="/tmp/ufw_backup.rules"
#####################################################

##################### FUNCTIONS #####################

# Prints text in a banner
function print_banner {
    echo
    echo "#######################################"
    echo "#"
    echo "#   $1"
    echo "#"
    echo "#######################################"
    echo
}

function debug_print {
    if [ "$debug" == "true" ]; then
        echo -n "DEBUG: "
        for arg in "$@"; do
            echo -n "$arg"
        done
        echo -e "\n"
    fi
}

function get_input_string {
    if [ "$ANSIBLE" == "true" ]; then
        echo ""
    else
        read -r -p "$1" input
        echo "$input"
    fi
}

function get_silent_input_string {
    if [ "$ANSIBLE" == "true" ]; then
        echo "DefaultPass123!"
    else
        read -r -s -p "$1" input
        echo "$input"
    fi
}

function get_input_list {
    if [ "$ANSIBLE" == "true" ]; then
        echo ""
    else
        local input_list=()
        while [ "$continue" != "false" ]; do
            input=$(get_input_string "Enter input: (one entry per line; hit enter to continue): ")
            if [ "$input" == "" ]; then
                continue="false"
            else
                input_list+=("$input")
            fi
        done
        echo "${input_list[@]}"
    fi
}

function exclude_users {
    if [ "$ANSIBLE" == "true" ]; then
        echo "$@"
    else
        users="$@"
        input=$(get_input_list)
        for item in $input; do
            users+=("$item")
        done
        echo "${users[@]}"
    fi
}

function get_users {
    awk_string=$1
    exclude_users=$(sed -e 's/ /\\|/g' <<< $2)
    users=$(awk -F ':' "$awk_string" /etc/passwd)
    filtered=$(echo "$users" | grep -v -e $exclude_users)
    readarray -t results <<< "$filtered"
    echo "${results[@]}"
}

function detect_system_info {
    print_banner "Detecting system info"
    echo "[*] Detecting package manager"
    sudo which apt-get &> /dev/null
    apt=$?
    sudo which dnf &> /dev/null
    dnf=$?
    sudo which zypper &> /dev/null
    zypper=$?
    sudo which yum &> /dev/null
    yum=$?

    if [ $apt == 0 ]; then
        echo "[*] apt/apt-get detected (Debian-based OS)"
        echo "[*] Updating package list"
        sudo apt-get update
        pm="apt-get"
    elif [ $dnf == 0 ]; then
        echo "[*] dnf detected (Fedora-based OS)"
        pm="dnf"
    elif [ $zypper == 0 ]; then
        echo "[*] zypper detected (OpenSUSE-based OS)"
        pm="zypper"
    elif [ $yum == 0 ]; then
        echo "[*] yum detected (RHEL-based OS)"
        pm="yum"
    else
        echo "[X] ERROR: Could not detect package manager"
        exit 1
    fi

    echo "[*] Detecting sudo group"
    groups=$(compgen -g)
    if echo "$groups" | grep -q '^sudo$'; then
        echo '[*] sudo group detected'
        sudo_group='sudo'
    elif echo "$groups" | grep -q '^wheel$'; then
        echo '[*] wheel group detected'
        sudo_group='wheel'
    else
        echo '[X] ERROR: could not detect sudo group'
        exit 1
    fi
}

function install_prereqs {
    print_banner "Installing prerequisites"
    sudo $pm install -y zip unzip wget curl acl
}

function change_root_password {
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping root password change."
        return 0
    fi
    print_banner "Changing Root Password"
    while true; do
        root_password=$(get_silent_input_string "Enter new root password: ")
        echo
        root_password_confirm=$(get_silent_input_string "Confirm new root password: ")
        echo
        if [ "$root_password" != "$root_password_confirm" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done
    if echo "root:$root_password" | sudo chpasswd; then
        echo "[*] Root password updated successfully."
    else
        echo "[X] ERROR: Failed to update root password."
    fi
}

function create_ccdc_users {
    if [ "$ANSIBLE" == "true" ]; then
        print_banner "Creating ccdc users (Ansible mode: Non-interactive)"
        default_password="ChangeMe123!"
        for user in "${ccdc_users[@]}"; do
            if ! id "$user" &>/dev/null; then
                if [ -f "/bin/bash" ]; then
                    sudo useradd -m -s /bin/bash "$user"
                else
                    sudo useradd -m -s /bin/sh "$user"
                fi
                echo "[*] Creating $user with default password."
                echo "$user:$default_password" | sudo chpasswd
                sudo usermod -aG $sudo_group "$user"
            else
                echo "[*] $user exists. Skipping interactive password update."
            fi
        done
        return 0
    fi
    print_banner "Creating ccdc users"
    for user in "${ccdc_users[@]}"; do
        if id "$user" &>/dev/null; then
            if [[ "$user" == "ccdcuser1" ]]; then
                echo "[*] $user already exists. Do you want to update the password? (y/N): "
                read -r update_choice
                if [[ "$update_choice" == "y" || "$update_choice" == "Y" ]]; then
                    while true; do
                        password=$(get_silent_input_string "Enter new password for $user: ")
                        echo
                        password_confirm=$(get_silent_input_string "Confirm new password for $user: ")
                        echo
                        if [ "$password" != "$password_confirm" ]; then
                            echo "Passwords do not match. Please retry."
                        else
                            if ! echo "$user:$password" | sudo chpasswd; then
                                echo "[X] ERROR: Failed to update password for $user"
                            else
                                echo "[*] Password for $user updated."
                                break
                            fi
                        fi
                    done
                fi
            elif [[ "$user" == "ccdcuser2" ]]; then
                echo "[*] $user already exists. Do you want to update the password? (y/N): "
                read -r update_choice
                if [[ "$update_choice" == "y" || "$update_choice" == "Y" ]]; then
                    while true; do
                        password=$(get_silent_input_string "Enter new password for $user: ")
                        echo
                        password_confirm=$(get_silent_input_string "Confirm new password for $user: ")
                        echo
                        if [ "$password" != "$password_confirm" ]; then
                            echo "Passwords do not match. Please retry."
                        else
                            if ! echo "$user:$password" | sudo chpasswd; then
                                echo "[X] ERROR: Failed to update password for $user"
                            else
                                echo "[*] Password for $user updated."
                                break
                            fi
                        fi
                    done
                fi
                echo "[*] Would you like to change the root password? (y/N): "
                read -r root_choice
                if [[ "$root_choice" == "y" || "$root_choice" == "Y" ]]; then
                    change_root_password
                fi
            else
                echo "[*] $user already exists. Skipping..."
            fi
        else
            echo "[*] $user not found. Creating user..."
            if [ -f "/bin/bash" ]; then
                sudo useradd -m -s /bin/bash "$user"
            elif [ -f "/bin/sh" ]; then
                sudo useradd -m -s /bin/sh "$user"
            else
                echo "[X] ERROR: Could not find valid shell"
                exit 1
            fi
            if [[ "$user" == "ccdcuser1" ]]; then
                echo "[*] Enter the password for $user:"
                while true; do
                    password=$(get_silent_input_string "Enter password for $user: ")
                    echo
                    password_confirm=$(get_silent_input_string "Confirm password for $user: ")
                    echo
                    if [ "$password" != "$password_confirm" ]; then
                        echo "Passwords do not match. Please retry."
                    else
                        if ! echo "$user:$password" | sudo chpasswd; then
                            echo "[X] ERROR: Failed to set password for $user"
                        else
                            echo "[*] Password for $user has been set."
                            break
                        fi
                    fi
                done
                echo "[*] Adding $user to $sudo_group group"
                sudo usermod -aG $sudo_group "$user"
            elif [[ "$user" == "ccdcuser2" ]]; then
                echo "[*] Enter the password for $user:"
                while true; do
                    password=$(get_silent_input_string "Enter password for $user: ")
                    echo
                    password_confirm=$(get_silent_input_string "Confirm password for $user: ")
                    echo
                    if [ "$password" != "$password_confirm" ]; then
                        echo "Passwords do not match. Please retry."
                    else
                        if ! echo "$user:$password" | sudo chpasswd; then
                            echo "[X] ERROR: Failed to set password for $user"
                        else
                            echo "[*] Password for $user has been set."
                            break
                        fi
                    fi
                done
                echo "[*] Would you like to change the root password? (y/N): "
                read -r root_choice
                if [[ "$root_choice" == "y" || "$root_choice" == "Y" ]]; then
                    change_root_password
                fi
            else
                if echo "$user:$default_password" | sudo chpasswd; then
                    echo "[*] $user created with the default password."
                else
                    echo "[X] ERROR: Failed to set default password for $user"
                fi
            fi
        fi
        echo
    done
}

function change_passwords {
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping bulk password change."
        return 0
    fi
    print_banner "Changing user passwords"
    exclusions=("root" "${ccdc_users[@]}")
    echo "[*] Currently excluded users: ${exclusions[*]}"
    echo "[*] Would you like to exclude any additional users?"
    option=$(get_input_string "(y/N): ")
    if [ "$option" == "y" ]; then
        exclusions=$(exclude_users "${exclusions[@]}")
    fi
    targets=$(get_users '$1 != "nobody" {print $1}' "${exclusions[*]}")
    echo "[*] Enter the new password to be used for all users."
    while true; do
        password=""
        confirm_password=""
        password=$(get_silent_input_string "Enter password: ")
        echo
        confirm_password=$(get_silent_input_string "Confirm password: ")
        echo
        if [ "$password" != "$confirm_password" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done
    echo
    echo "[*] Changing passwords..."
    for user in $targets; do
        if ! echo "$user:$password" | sudo chpasswd; then
            echo "[X] ERROR: Failed to change password for $user"
        else
            echo "[*] Password for $user has been changed."
        fi
    done
}

function disable_users {
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping user disabling."
        return 0
    fi
    print_banner "Disabling users"
    exclusions=("${ccdc_users[@]}")
    exclusions+=("root")
    echo "[*] Currently excluded users: ${exclusions[*]}"
    echo "[*] Would you like to exclude any additional users?"
    option=$(get_input_string "(y/N): ")
    if [ "$option" == "y" ]; then
        exclusions=$(exclude_users "${exclusions[@]}")
    fi
    targets=$(get_users '/\/bash$|\/sh$|\/ash$|\/zsh$/{print $1}' "${exclusions[*]}")
    echo
    echo "[*] Disabling user accounts using usermod -L and setting shell to nologin..."
    for user in $targets; do
        if sudo usermod -L "$user"; then
            echo "[*] Account for $user has been locked (usermod -L)."
            if sudo usermod -s /usr/sbin/nologin "$user"; then
                echo "[*] Login shell for $user set to nologin."
            else
                echo "[X] ERROR: Failed to set nologin shell for $user."
            fi
        else
            echo "[X] ERROR: Failed to lock account for $user using usermod -L."
        fi
    done
}

function remove_sudoers {
    print_banner "Removing sudoers"
    echo "[*] Removing users from the $sudo_group group"
    exclusions=("ccdcuser1")
    echo "[*] Currently excluded users: ${exclusions[*]}"
    echo "[*] Would you like to exclude any additional users?"
    option=$(get_input_string "(y/N): ")
    if [ "$option" == "y" ]; then
        exclusions=$(exclude_users "${exclusions[@]}")
    fi
    targets=$(get_users '{print $1}' "${exclusions[*]}")
    echo
    echo "[*] Removing sudo users..."
    for user in $targets; do
        if groups "$user" | grep -q "$sudo_group"; then
            echo "[*] Removing $user from $sudo_group group"
            sudo gpasswd -d "$user" "$sudo_group"
        fi
    done
}

function audit_running_services {
    print_banner "Auditing Running Services"
    echo "[*] Listing running services (TCP/UDP listening ports):"
    ss -tuln
}

function disable_other_firewalls {
    print_banner "Disabling existing firewalls"
    if sudo command -v firewalld &>/dev/null; then
        echo "[*] Disabling firewalld"
        sudo systemctl stop firewalld
        sudo systemctl disable firewalld
    fi
}

########################################################################
# FUNCTION: backup_current_iptables_rules
########################################################################
function backup_current_iptables_rules {
    if grep -qi 'fedora\|centos\|rhel' /etc/os-release; then
        sudo iptables-save | sudo tee /etc/sysconfig/iptables > /dev/null
        echo "[*] Iptables rules saved to /etc/sysconfig/iptables"
    elif grep -qi 'suse' /etc/os-release; then
        sudo iptables-save | sudo tee /etc/sysconfig/iptables > /dev/null
        echo "[*] Iptables rules saved to /etc/sysconfig/iptables (SUSE)"
    elif grep -qi 'debian\|ubuntu' /etc/os-release; then
        if [ -f /etc/iptables/rules.v4 ]; then
            sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null
            echo "[*] Iptables rules saved to /etc/iptables/rules.v4"
        elif command -v netfilter-persistent &> /dev/null; then
            sudo netfilter-persistent save
            echo "[*] Iptables rules saved using netfilter-persistent"
        else
            echo "[!] Warning: iptables persistent saving is not configured on this system."
        fi
    else
        echo "[*] Unknown OS. Please ensure iptables rules are saved manually if needed."
    fi
}

function backup_current_ufw_rules {
    echo "[*] Backing up current UFW rules to $UFW_BACKUP"
    sudo cp /etc/ufw/user.rules "$UFW_BACKUP"
}

function restore_ufw_rules {
    if [ -f "$UFW_BACKUP" ]; then
        echo "[*] Restoring UFW rules from $UFW_BACKUP"
        sudo ufw reset
        sudo cp "$UFW_BACKUP" /etc/ufw/user.rules
        sudo ufw reload
    else
        echo "[X] No UFW backup file found."
    fi
}

########################################################################
# FUNCTION: setup_ufw
########################################################################
function setup_ufw {
    print_banner "Configuring ufw"
    sudo $pm install -y ufw
    sudo sed -i 's/^IPV6=yes/IPV6=no/' /etc/default/ufw
    sudo ufw --force disable
    sudo ufw --force reset
    sudo ufw default deny outgoing
    sudo ufw default deny incoming
    sudo ufw allow out on lo
    sudo ufw allow out to any port 53 proto tcp
    sudo ufw allow out to any port 53 proto udp
    echo -e "[*] UFW installed and configured with strict outbound deny (except DNS) successfully.\n"
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping additional inbound port configuration."
    else
        echo "[*] Which additional ports should be opened for incoming traffic?"
        echo "      WARNING: Do NOT forget to add 22/SSH if needed - please don't accidentally lock yourself out!"
        ports=$(get_input_list)
        for port in $ports; do
            sudo ufw allow "$port"
            echo "[*] Rule added for port $port"
        done
    fi
    sudo ufw logging on
    sudo ufw --force enable
    backup_current_ufw_rules
}

########################################################################
# FUNCTION: ufw_disable_default_deny
########################################################################
function ufw_disable_default_deny {
    print_banner "Temporarily Disabling UFW Default Deny Outgoing Policy"
    sudo ufw default allow outgoing
    echo "[*] UFW default outgoing policy is now set to allow."
    backup_current_ufw_rules
}

########################################################################
# FUNCTION: ufw_enable_default_deny
########################################################################
function ufw_enable_default_deny {
    print_banner "Re-enabling UFW Default Deny Outgoing Policy"
    sudo ufw default deny outgoing
    sudo ufw allow out on lo
    sudo ufw allow out to any port 53 proto tcp
    sudo ufw allow out to any port 53 proto udp
    echo "[*] UFW default outgoing policy is now set to deny."
    backup_current_ufw_rules
}

########################################################################
# FUNCTION: setup_custom_iptables
########################################################################
function setup_custom_iptables {
    print_banner "Configuring iptables (Custom Script)"
    reset_iptables

    # Set default policies: DROP for INPUT and OUTPUT
    sudo iptables -P OUTPUT DROP
    sudo iptables -P INPUT DROP

    # Allow loopback traffic by default.
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT

    # (Optional) Drop FORWARD chain (if this box is not a router)
    sudo iptables -P FORWARD DROP
    echo "[WARNING] FORWARD chain is set to DROP. If this box is a router or network device, please run 'sudo iptables -P FORWARD ALLOW'."

    # Allow established/related connections.
    sudo iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # Allow outbound DNS queries.
    sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
    sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    # Allow inbound DNS traffic.
    sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
    sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT

    # Allow ICMP traffic (for pings).
    sudo iptables -A INPUT -p icmp -j ACCEPT
    sudo iptables -A OUTPUT -p icmp -j ACCEPT

    # Allow outbound HTTPS (443) and HTTP (80) by default.
    sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
    sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT

    # Read current running TCP listening ports and allow inbound traffic (except port 53).
    running_ports=$(ss -lnt | awk 'NR>1 {split($4,a,":"); print a[length(a)]}' | sort -nu)
    for port in $running_ports; do
        if [ "$port" != "53" ]; then
            sudo iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        fi
    done

    echo "Select your DNS server option:"
    echo "  1) Use Cloudflare DNS servers (1.1.1.1, 1.0.0.1)"
    echo "  2) Use default gateway/router as your DNS server"
    echo "  3) Use default DNS servers (192.168.XXX.1, 192.168.XXX.2)"
    if [ "$ANSIBLE" == "true" ]; then
        dns_choice="1"
        echo "[*] Ansible mode: Defaulting DNS server option to 1."
    else
        dns_choice=$(get_input_string "Enter your choice [1-3]: ")
    fi
    if [[ "$dns_choice" == "1" ]]; then
        dns_value="1.1.1.1 1.0.0.1"
    elif [[ "$dns_choice" == "2" ]]; then
        default_gateway=$(ip route | awk '/default/ {print $3; exit}')
        if [[ -z "$default_gateway" ]]; then
            echo "[X] Could not determine default gateway. Using fallback DNS servers."
            dns_value="192.168.XXX.1 192.168.XXX.2"
        else
            dns_value="$default_gateway"
        fi
    else
        dns_value="192.168.XXX.1 192.168.XXX.2"
    fi
    backup_current_iptables_rules
    if [ "$ANSIBLE" == "false" ]; then
        ext_choice=$(get_input_string "Would you like to add any additional iptables rules? (y/N): ")
        if [[ "$ext_choice" == "y" || "$ext_choice" == "Y" ]]; then
            extended_iptables
        fi
    else
        echo "[*] Ansible mode: Skipping additional iptables rule prompts."
    fi
}

########################################################################
# FUNCTION: open_ossec_ports
########################################################################
function open_ossec_ports {
    print_banner "Opening OSSEC Ports"
    sudo iptables -A OUTPUT -p udp --dport 1514 -j ACCEPT
    sudo iptables -A OUTPUT -p udp --dport 1515 -j ACCEPT
    echo "[*] OSSEC outbound ports 1514 and 1515 (UDP) have been opened."
    backup_current_iptables_rules
}

########################################################################
# FUNCTION: apply_established_only_rules
########################################################################
function apply_established_only_rules {
    print_banner "Applying Established/Related Only Rules"
    reset_iptables
    sudo iptables -P INPUT DROP
    sudo iptables -P OUTPUT DROP
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    backup_current_iptables_rules
}

########################################################################
# FUNCTION: iptables_disable_default_deny
########################################################################
function iptables_disable_default_deny {
    print_banner "Temporarily Disabling iptables Default Deny Outgoing Policy"
    backup_current_iptables_rules
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -P INPUT ACCEPT
    echo "[*] iptables default policies are now set to ACCEPT (backup saved)."
}

########################################################################
# FUNCTION: iptables_enable_default_deny
########################################################################
function iptables_enable_default_deny {
    print_banner "Re-enabling iptables Default Deny Outgoing Policy"
    backup_current_iptables_rules
    sudo iptables -P OUTPUT DROP
    sudo iptables -P INPUT DROP
    echo "[*] iptables default policies are now set to DROP (current rules preserved)."
}

########################################################################
# FUNCTION: custom_iptables_manual_rules (inbound)
########################################################################
function custom_iptables_manual_rules {
    print_banner "Manual Inbound IPtables Rule Addition"
    echo "[*] Enter port numbers (one per line) for which you wish to allow inbound TCP traffic."
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping manual inbound rule addition."
        return 0
    fi
    echo "    Press ENTER on a blank line when finished."
    ports=$(get_input_list)
    for port in $ports; do
        sudo iptables -A INPUT --protocol tcp --dport "$port" -j ACCEPT
        echo "[*] Inbound iptables rule added for port $port (TCP)"
        backup_current_iptables_rules
    done
}

########################################################################
# FUNCTION: custom_iptables_manual_outbound_rules
########################################################################
function custom_iptables_manual_outbound_rules {
    print_banner "Manual Outbound IPtables Rule Addition"
    echo "[*] Enter port numbers (one per line) for which you wish to allow outbound TCP traffic."
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping manual outbound rule addition."
        return 0
    fi
    echo "    Press ENTER on a blank line when finished."
    ports=$(get_input_list)
    for port in $ports; do
        sudo iptables -A OUTPUT --protocol tcp --dport "$port" -j ACCEPT
        echo "[*] Outbound iptables rule added for port $port (TCP)"
        backup_current_iptables_rules
    done
}

########################################################################
# FUNCTION: extended_iptables
########################################################################
function extended_iptables {
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping extended iptables management."
        return 0
    fi
    while true; do
        print_banner "Extended IPtables Management"
        echo "Select an option:"
        echo "  1) Add Outbound Rule (ACCEPT)"
        echo "  2) Add Inbound Rule (ACCEPT)"
        echo "  3) Deny Outbound Rule (DROP)"
        echo "  4) Deny Inbound Rule (DROP)"
        echo "  5) Show All Rules"
        echo "  6) Reset Firewall"
        echo "  7) Exit Extended IPtables Management"
        read -p "Enter your choice [1-7]: " choice
        case $choice in
            1)
                read -p "Enter outbound port number: " port
                sudo iptables -A OUTPUT --protocol tcp --dport "$port" -j ACCEPT
                echo "Outbound ACCEPT rule added for port $port"
                backup_current_iptables_rules
                ;;
            2)
                read -p "Enter inbound port number: " port
                sudo iptables -A INPUT --protocol tcp --dport "$port" -j ACCEPT
                echo "Inbound ACCEPT rule added for port $port"
                backup_current_iptables_rules
                ;;
            3)
                read -p "Enter outbound port number to deny: " port
                sudo iptables -A OUTPUT --protocol tcp --dport "$port" -j DROP
                echo "Outbound DROP rule added for port $port"
                backup_current_iptables_rules
                ;;
            4)
                read -p "Enter inbound port number to deny: " port
                sudo iptables -A INPUT --protocol tcp --dport "$port" -j DROP
                echo "Inbound DROP rule added for port $port"
                backup_current_iptables_rules
                ;;
            5)
                sudo iptables -L -n -v
                ;;
            6)
                reset_iptables
                backup_current_iptables_rules
                ;;
            7)
                echo "Exiting Extended IPtables Management."
                break
                ;;
            *)
                echo "Invalid option selected."
                ;;
        esac
        echo ""
    done
}

########################################################################
# FUNCTION: reset_iptables
########################################################################
function reset_iptables {
    print_banner "Resetting IPtables Firewall"
    echo "[*] Flushing all iptables rules..."
    sudo iptables -F
    sudo iptables -X
    sudo iptables -Z
    echo "[*] Setting default policies to ACCEPT..."
    sudo iptables -P INPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT
    sudo iptables -P OUTPUT ACCEPT
    echo "[*] IPtables firewall has been reset."
    backup_current_iptables_rules
}

########################################################################
# FUNCTION: firewall_configuration_menu
########################################################################
function firewall_configuration_menu {
    detect_system_info
    install_prereqs
    disable_other_firewalls
    audit_running_services
    if [ "$ANSIBLE" == "true" ]; then
         echo "[*] Ansible mode: Running default firewall configuration (iptables)."
         setup_custom_iptables
         return 0
    fi
    read -p "Press ENTER to continue to the firewall configuration menu..." dummy
    echo
    echo "Select firewall type:"
    echo "  1) UFW"
    echo "  2) IPtables"
    read -p "Enter your choice [1-2]: " fw_type_choice
    echo
    case $fw_type_choice in
        1)
            while true; do
                echo "===== UFW Menu ====="
                echo "  1) Setup UFW"
                echo "  2) Create inbound allow rule"
                echo "  3) Create outbound allow rule"
                echo "  4) Show UFW rules"
                echo "  5) Reset UFW"
                echo "  6) Show Running Services"
                echo "  7) Disable default deny (temporarily allow outbound)"
                echo "  8) Enable default deny (restore outbound blocking)"
                echo "  9) Exit UFW menu"
                read -p "Enter your choice [1-9]: " ufw_choice
                echo
                case $ufw_choice in
                    1)
                        setup_ufw
                        ;;
                    2)
                        echo "[*] Enter inbound port numbers (one per line; hit ENTER on a blank line to finish):"
                        ports=$(get_input_list)
                        for port in $ports; do
                            sudo ufw allow in "$port"
                            echo "[*] Inbound allow rule added for port $port"
                        done
                        ;;
                    3)
                        echo "[*] Enter outbound port numbers (one per line; hit ENTER on a blank line to finish):"
                        ports=$(get_input_list)
                        for port in $ports; do
                            sudo ufw allow out "$port"
                            echo "[*] Outbound allow rule added for port $port"
                        done
                        ;;
                    4)
                        sudo ufw status numbered
                        ;;
                    5)
                        echo "[*] Resetting UFW..."
                        sudo ufw --force reset
                        ;;
                    6)
                        audit_running_services
                        ;;
                    7)
                        ufw_disable_default_deny
                        ;;
                    8)
                        ufw_enable_default_deny
                        ;;
                    9)
                        break
                        ;;
                    *)
                        echo "[X] Invalid option."
                        ;;
                esac
                echo
            done
            ;;
        2)
            while true; do
                echo "===== IPtables Menu ====="
                echo "  1) Setup IPtables"
                echo "  2) Create outbound allow rule"
                echo "  3) Create inbound allow rule"
                echo "  4) Create outbound deny rule"
                echo "  5) Create inbound deny rule"
                echo "  6) Show IPtables rules"
                echo "  7) Reset IPtables"
                echo "  8) Show Running Services"
                echo "  9) Disable default deny (temporarily allow outbound)"
                echo "  10) Enable default deny (restore outbound blocking)"
                echo "  11) Open OSSEC Ports (UDP 1514 & 1515)"
                echo "  12) Allow only Established/Related Traffic"
                echo "  13) Exit IPtables menu"
                read -p "Enter your choice [1-13]: " ipt_choice
                echo
                case $ipt_choice in
                    1)
                        setup_custom_iptables
                        ;;
                    2)
                        custom_iptables_manual_outbound_rules
                        ;;
                    3)
                        custom_iptables_manual_rules
                        ;;
                    4)
                        read -p "Enter outbound port number to deny: " port
                        sudo iptables -A OUTPUT --protocol tcp --dport "$port" -j DROP
                        echo "[*] Outbound deny rule added for port $port"
                        backup_current_iptables_rules
                        ;;
                    5)
                        read -p "Enter inbound port number to deny: " port
                        sudo iptables -A INPUT --protocol tcp --dport "$port" -j DROP
                        echo "[*] Inbound deny rule added for port $port"
                        backup_current_iptables_rules
                        ;;
                    6)
                        sudo iptables -L -n -v
                        ;;
                    7)
                        reset_iptables
                        backup_current_iptables_rules
                        ;;
                    8)
                        audit_running_services
                        ;;
                    9)
                        iptables_disable_default_deny
                        ;;
                    10)
                        iptables_enable_default_deny
                        ;;
                    11)
                        open_ossec_ports
                        ;;
                    12)
                        apply_established_only_rules
                        ;;
                    13)
                        break
                        ;;
                    *)
                        echo "[X] Invalid option."
                        ;;
                esac
                echo
            done
            ;;
        *)
            echo "[X] Invalid firewall type selection."
            ;;
    esac
}

########################################################################
# FUNCTION: backup_directories
########################################################################
function backup_directories {
    print_banner "Backup Directories"
    default_dirs=( "/etc/nginx" "/etc/apache2" "/usr/share/nginx" "/var/www" "/var/www/html" "/etc/lighttpd" "/etc/mysql" "/etc/postgresql" "/var/lib/apache2" "/var/lib/mysql" "/etc/redis" "/etc/phpMyAdmin" "/etc/php.d" )
    detected_dirs=()
    echo "[*] Scanning for critical directories..."
    for d in "${default_dirs[@]}"; do
        if [ -d "$d" ]; then
            detected_dirs+=("$d")
        fi
    done
    backup_list=()
    if [ ${#detected_dirs[@]} -gt 0 ]; then
        echo "[*] The following critical directories were detected:"
        for d in "${detected_dirs[@]}"; do
            echo "   $d"
        done
        if [ "$ANSIBLE" == "true" ]; then
            backup_list=("${detected_dirs[@]}")
            echo "[*] Ansible mode: Automatically backing up detected directories."
        else
            read -p "Would you like to back these up? (y/N): " detected_choice
            if [[ "$detected_choice" == "y" || "$detected_choice" == "Y" ]]; then
                backup_list=("${detected_dirs[@]}")
            fi
        fi
    else
        echo "[*] No critical directories detected."
    fi
    if [ "$ANSIBLE" != "true" ]; then
        read -p "Would you like to backup any additional files or directories? (y/N): " additional_choice
        if [[ "$additional_choice" == "y" || "$additional_choice" == "Y" ]]; then
            echo "[*] Enter additional directories/files to backup (one per line; hit ENTER on a blank line to finish):"
            additional_dirs=$(get_input_list)
            for item in $additional_dirs; do
                path=$(readlink -f "$item")
                if [ -e "$path" ]; then
                    backup_list+=("$path")
                else
                    echo "[X] ERROR: $path does not exist."
                fi
            done
        fi
    fi
    if [ ${#backup_list[@]} -eq 0 ]; then
        echo "[*] No directories or files selected for backup. Exiting backup."
        return
    fi
    while true; do
        backup_name=$(get_input_string "Enter a name for the backup archive (without extension .zip): ")
        if [ "$backup_name" != "" ]; then
            if [[ "$backup_name" != *.zip ]]; then
                backup_name="${backup_name}.zip"
            fi
            break
        fi
        echo "[X] ERROR: Backup name cannot be blank."
    done
    echo "[*] Creating archive..."
    zip -r "$backup_name" "${backup_list[@]}" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "[X] ERROR: Failed to create archive."
        return
    fi
    echo "[*] Archive created: $backup_name"
    echo "[*] Encrypting the archive."
    while true; do
        enc_password=$(get_silent_input_string "Enter encryption password: ")
        echo
        enc_confirm=$(get_silent_input_string "Confirm encryption password: ")
        echo
        if [ "$enc_password" != "$enc_confirm" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done
    enc_archive="${backup_name}.enc"
    openssl enc -aes-256-cbc -salt -in "$backup_name" -out "$enc_archive" -k "$enc_password"
    if [ $? -ne 0 ]; then
        echo "[X] ERROR: Encryption failed."
        return
    fi
    echo "[*] Archive encrypted: $enc_archive"
    while true; do
        storage_dir=$(get_input_string "Enter directory to store the encrypted backup: ")
        storage_dir=$(readlink -f "$storage_dir")
        if [ -d "$storage_dir" ]; then
            break
        else
            echo "[*] Directory does not exist. Creating it..."
            sudo mkdir -p "$storage_dir"
            if [ $? -eq 0 ]; then
                break
            else
                echo "[X] ERROR: Could not create directory."
            fi
        fi
    done
    sudo mv "$enc_archive" "$storage_dir/"
    if [ $? -eq 0 ]; then
        echo "[*] Encrypted archive moved to $storage_dir"
    else
        echo "[X] ERROR: Failed to move encrypted archive."
    fi
    rm -f "$backup_name"
    echo "[*] Cleanup complete. Only the encrypted archive remains."
}

########################################################################
# FUNCTION: unencrypt_backups
########################################################################
function unencrypt_backups {
    print_banner "Decrypt Backup"
    while true; do
        encrypted_file=$(get_input_string "Enter path to the encrypted backup file: ")
        encrypted_file=$(readlink -f "$encrypted_file")
        if [ ! -f "$encrypted_file" ]; then
            echo "[X] ERROR: File '$encrypted_file' does not exist."
            dir=$(dirname "$encrypted_file")
            base=$(basename "$encrypted_file")
            echo "[*] Searching for similar files in '$dir'..."
            similar_files=$(find "$dir" -maxdepth 1 -iname "*${base}*" 2>/dev/null)
            if [ -n "$similar_files" ]; then
                echo "[*] Similar files found:"
                echo "$similar_files"
            else
                echo "[*] No similar files found."
            fi
            echo "[*] Please try again."
        else
            break
        fi
    done
    while true; do
        dec_password=$(get_silent_input_string "Enter decryption password: ")
        echo
        dec_confirm=$(get_silent_input_string "Confirm decryption password: ")
        echo
        if [ "$dec_password" != "$dec_confirm" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done
    temp_output="decrypted_backup.zip"
    openssl enc -d -aes-256-cbc -in "$encrypted_file" -out "$temp_output" -k "$dec_password"
    if [ $? -ne 0 ]; then
        echo "[X] ERROR: Decryption failed. Check your password."
        rm -f "$temp_output"
        return
    fi
    echo "[*] Decryption successful. Decrypted archive: $temp_output"
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping extraction of decrypted archive."
    else
        read -p "Would you like to extract the decrypted archive? (y/N): " extract_choice
        if [[ "$extract_choice" == "y" || "$extract_choice" == "Y" ]]; then
            read -p "Enter directory to extract the backup: " extract_dir
            extract_dir=$(readlink -f "$extract_dir")
            mkdir -p "$extract_dir"
            unzip "$temp_output" -d "$extract_dir"
            echo "[*] Backup extracted to $extract_dir"
            rm -f "$temp_output"
        else
            echo "[*] Decrypted archive remains as $temp_output"
        fi
    fi
}

# In Ansible mode, skip the backup section entirely.
function backups {
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping backup section."
        return 0
    fi
    print_banner "Backup Menu"
    echo "1) Backup Directories"
    echo "2) Decrypt Backup"
    echo "3) Exit Backup Menu"
    read -p "Enter your choice [1-3]: " backup_choice
    case $backup_choice in
        1)
            backup_directories
            ;;
        2)
            unencrypt_backups
            ;;
        3)
            echo "[*] Exiting Backup Menu."
            ;;
        *)
            echo "[X] Invalid option."
            ;;
    esac
}

function setup_splunk {
    print_banner "Installing Splunk"
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping Splunk installation."
        return 0
    fi
    indexer_ip=$(get_input_string "What is the Splunk forward server ip? ")
    wget $GITHUB_URL/splunk/splunk.sh --no-check-certificate
    chmod +x splunk.sh
    ./splunk.sh -f $indexer_ip
}

##################### ADDITIONAL WEB HARDENING FUNCTIONS #####################
function backup_databases {
    print_banner "Hardening Databases"
    sudo service mysql status >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[+] mysql/mariadb is active!"
        sudo mysql -u root -e "quit" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "[!] Able to login with empty password on the mysql database!"
            echo "[*] Backing up all databases..."
            sudo mysqldump --all-databases > backup.sql
            ns=$(date +%N)
            pass=$(echo "${ns}$REPLY" | sha256sum | cut -d" " -f1)
            echo "[+] Backed up database. Key for database dump: $pass"
            gpg -c --pinentry-mode=loopback --passphrase "$pass" backup.sql
            sudo rm backup.sql
        fi
    fi
    sudo service postgresql status >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[+] PostgreSQL is active!"
    fi
}

function secure_php_ini {
    print_banner "Securing php.ini Files"
    for ini in $(find / -name "php.ini" 2>/dev/null); do
        echo "[+] Writing php.ini options to $ini..."
        echo "disable_functions = shell_exec, exec, passthru, proc_open, popen, system, phpinfo" | sudo tee -a "$ini" >/dev/null
        echo "max_execution_time = 3" | sudo tee -a "$ini" >/dev/null
        echo "register_globals = off" | sudo tee -a "$ini" >/dev/null
        echo "magic_quotes_gpc = on" | sudo tee -a "$ini" >/dev/null
        echo "allow_url_fopen = off" | sudo tee -a "$ini" >/dev/null
        echo "allow_url_include = off" | sudo tee -a "$ini" >/dev/null
        echo "display_errors = off" | sudo tee -a "$ini" >/dev/null
        echo "short_open_tag = off" | sudo tee -a "$ini" >/dev/null
        echo "session.cookie_httponly = 1" | sudo tee -a "$ini" >/dev/null
        echo "session.use_only_cookies = 1" | sudo tee -a "$ini" >/dev/null
        echo "session.cookie_secure = 1" | sudo tee -a "$ini" >/dev/null
    done
}

function configure_login_banner {
    print_banner "Configuring Login Banner"

    # Define the banner file and default banner text.
    local banner_file="/etc/issue.net"
    local default_banner="WARNING: UNAUTHORIZED ACCESS TO THIS NETWORK DEVICE IS PROHIBITED
You must have explicit, authorized permission to access or configure this device.
Unauthorized attempts to access and misuse of this system may result in prosecution.
All activities performed on this device are logged and monitored.

WARNING: This computer system is the property of Team ##.
This computer system, including all related equipment, networks, and network devices, is for authorized users only.
All activity on this network is being monitored and logged for lawful purposes, including verifying authorized use.

Data collected including logs will be used to investigate and prosecute unauthorized or improper access.
By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use.

All employees must take reasonable steps to prevent unauthorized access to the system, including protecting passwords and other login information.
Employees are required to notify their administrators immediately of any known or suspected breach of security and to do their best to stop such a breach."

    # Write the banner text to /etc/issue.net.
    echo "$default_banner" | sudo tee "$banner_file" >/dev/null
    echo "[*] Login banner written to $banner_file."

    # Update SSH configuration to use the banner.
    local ssh_config="/etc/ssh/sshd_config"
    if [ -f "$ssh_config" ]; then
        # Remove any pre-existing Banner directives.
        sudo sed -i '/^Banner/d' "$ssh_config"
        # Append the new Banner line.
        echo "Banner $banner_file" | sudo tee -a "$ssh_config" >/dev/null
        echo "[*] Updated $ssh_config to use the login banner."
        # Restart the SSH service.
        if command -v systemctl >/dev/null 2>&1; then
            sudo systemctl restart sshd
        else
            sudo service ssh restart
        fi
        echo "[*] SSH service restarted."
    else
        echo "[X] SSH configuration file not found at $ssh_config."
    fi
}

function secure_ssh {
    print_banner "Securing SSH"

    # Determine SSH service name.
    if sudo service sshd status > /dev/null 2>&1; then
        service_name="sshd"
    elif sudo service ssh status > /dev/null 2>&1; then
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

    # Backup current sshd_config
    sudo cp "$config_file" "${config_file}.bak"

    # 1. Disable Root Login
    sudo sed -i '/^PermitRootLogin/d' "$config_file"
    echo "PermitRootLogin no" | sudo tee -a "$config_file" >/dev/null

    # 2. Allow only specific users or groups - uncomment and modify as needed.
    # echo "AllowUsers ccdcuser1 ccdcuser2" | sudo tee -a "$config_file" >/dev/null
    # echo "AllowGroups admin" | sudo tee -a "$config_file" >/dev/null

    # 3. Deny specific users or groups - uncomment and modify as needed.
    # echo "DenyUsers apache www-data" | sudo tee -a "$config_file" >/dev/null
    # echo "DenyGroups somegroup" | sudo tee -a "$config_file" >/dev/null

    # 4. Change SSH port if desired.
    # echo "Port 222" | sudo tee -a "$config_file" >/dev/null

    # 5. Change Login Grace Time to 1 minute.
    sudo sed -i '/^LoginGraceTime/d' "$config_file"
    echo "LoginGraceTime 1m" | sudo tee -a "$config_file" >/dev/null

    # 6. Restrict the interface(s) via ListenAddress - uncomment and modify as needed.
    # echo "ListenAddress 192.168.10.200" | sudo tee -a "$config_file" >/dev/null

    # 7. Set SSH idle timeout (ClientAliveInterval and ClientAliveCountMax).
    sudo sed -i '/^ClientAliveInterval/d' "$config_file"
    sudo sed -i '/^ClientAliveCountMax/d' "$config_file"
    echo "ClientAliveInterval 600" | sudo tee -a "$config_file" >/dev/null
    echo "ClientAliveCountMax 0" | sudo tee -a "$config_file" >/dev/null

    # Additional recommended settings:
    # Deny empty passwords.
    sudo sed -i '/^PermitEmptyPasswords/d' "$config_file"
    echo "PermitEmptyPasswords no" | sudo tee -a "$config_file" >/dev/null

    # Set AddressFamily to inet (IPv4 only).
    sudo sed -i '/^AddressFamily/d' "$config_file"
    echo "AddressFamily inet" | sudo tee -a "$config_file" >/dev/null

    # Disable DNS lookups for connecting clients.
    sudo sed -i '/^UseDNS/d' "$config_file"
    echo "UseDNS no" | sudo tee -a "$config_file" >/dev/null

    # Test SSH configuration.
    if sudo sshd -t; then
        # Restart the SSH service.
        if command -v systemctl >/dev/null 2>&1; then
            sudo systemctl restart "$service_name"
        else
            sudo service "$service_name" restart
        fi
        echo "[*] SSH hardening applied and $service_name restarted."
    else
        echo "[X] ERROR: SSH configuration test failed. Restoring original configuration."
        sudo cp "${config_file}.bak" "$config_file"
    fi
}

#########################################################
# MODSECURITY SECTION
#########################################################

# Determine the recommended ModSecurity Docker image tag based on the OS.
# Supports Ubuntu (14,16,18,20,22), CentOS (6,7,8,9), Debian (7–12), Fedora (25–35),
# and OpenSUSE (Leap and Tumbleweed). If no explicit mapping exists, falls back to 'latest'.
function get_modsecurity_image {
    # Source OS info
    if [ -f /etc/os-release ]; then
        . /etc/os-release
    fi
    distro=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
    version_major=$(echo "$VERSION_ID" | cut -d. -f1)

    # Define mappings for various distributions
    declare -A modsec_map_ubuntu=( ["14"]="modsecurity/modsecurity:ubuntu14.04" ["16"]="modsecurity/modsecurity:ubuntu16.04" ["18"]="modsecurity/modsecurity:ubuntu18.04" ["20"]="modsecurity/modsecurity:ubuntu20.04" ["22"]="modsecurity/modsecurity:ubuntu22.04" )
    declare -A modsec_map_centos=( ["6"]="modsecurity/modsecurity:centos6" ["7"]="modsecurity/modsecurity:centos7" ["8"]="modsecurity/modsecurity:centos8" ["9"]="modsecurity/modsecurity:centos:stream9" )
    declare -A modsec_map_debian=( ["7"]="modsecurity/modsecurity:debian7" ["8"]="modsecurity/modsecurity:debian8" ["9"]="modsecurity/modsecurity:debian9" ["10"]="modsecurity/modsecurity:debian10" ["11"]="modsecurity/modsecurity:debian11" ["12"]="modsecurity/modsecurity:debian12" )
    declare -A modsec_map_fedora=( ["25"]="modsecurity/modsecurity:fedora25" ["26"]="modsecurity/modsecurity:fedora26" ["27"]="modsecurity/modsecurity:fedora27" ["28"]="modsecurity/modsecurity:fedora28" ["29"]="modsecurity/modsecurity:fedora29" ["30"]="modsecurity/modsecurity:fedora30" ["31"]="modsecurity/modsecurity:fedora31" ["35"]="modsecurity/modsecurity:fedora35" )

    # OpenSUSE: check PRETTY_NAME for a keyword match
    if [[ "$PRETTY_NAME" =~ Tumbleweed ]]; then
         echo "modsecurity/modsecurity:opensuse-tumbleweed"
         return 0
    elif [[ "$PRETTY_NAME" =~ Leap ]]; then
         echo "modsecurity/modsecurity:opensuse-leap"
         return 0
    fi

    local image=""
    if [[ "$distro" == "ubuntu" ]]; then
         image=${modsec_map_ubuntu[$version_major]:-"modsecurity/modsecurity:latest"}
    elif [[ "$distro" == "centos" ]]; then
         image=${modsec_map_centos[$version_major]:-"modsecurity/modsecurity:latest"}
    elif [[ "$distro" == "debian" ]]; then
         image=${modsec_map_debian[$version_major]:-"modsecurity/modsecurity:latest"}
    elif [[ "$distro" == "fedora" ]]; then
         image=${modsec_map_fedora[$version_major]:-"modsecurity/modsecurity:latest"}
    else
         image="modsecurity/modsecurity:latest"
    fi
    echo "$image"
}

# Generate a strict (maximum security) ModSecurity configuration file.
function generate_strict_modsec_conf {
    local conf_file="/tmp/modsecurity_strict.conf"
    print_banner "Generating Strict ModSecurity Configuration"
    sudo bash -c "cat > $conf_file" <<'EOF'
# Strict ModSecurity Configuration for Maximum Protection

SecRuleEngine On
SecDefaultAction "phase:1,deny,log,status:403"
SecRequestBodyAccess On
SecResponseBodyAccess Off

# Block file uploads by denying requests with file parameters.
SecRule ARGS_NAMES "@rx .*" "id:1000,phase:2,deny,status:403,msg:'File upload detected; blocking.'"

# Set temporary directories (ensure OS-level security on these paths)
SecTmpDir /tmp/modsec_tmp
SecDataDir /tmp/modsec_data

# Enable detailed audit logging.
SecAuditEngine On
SecAuditLogParts ABIJDEFHZ
SecAuditLog /var/log/modsecurity_audit.log

# Limit PCRE usage for performance and to mitigate complex regex attacks.
SecPcreMatchLimit 1000
SecPcreMatchLimitRecursion 1000

# Restrict request and response body sizes.
SecResponseBodyLimit 524288
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
EOF
    echo "[*] Strict ModSecurity config generated at $conf_file"
    echo "$conf_file"
}

# Dockerized ModSecurity installation function (runs by default)
# This function is used for both Ansible and regular execution.
function install_modsecurity_docker {
    print_banner "Dockerized ModSecurity Installation (Strict Mode)"
    # Ensure Docker is installed
    if ! ensure_docker_installed; then
        echo "[X] Could not install Docker automatically. Aborting."
        return 1
    fi

    # Determine the Docker image; in Ansible mode, use the recommended image automatically.
    local image
    if [ "$ANSIBLE" == "true" ]; then
        image=$(get_modsecurity_image)
        echo "[*] Ansible mode: Using recommended ModSecurity Docker image: $image"
    else
        local default_image
        default_image=$(get_modsecurity_image)
        read -p "Enter ModSecurity Docker image to use [default: $default_image]: " user_image
        if [ -n "$user_image" ]; then
            image="$user_image"
        else
            image="$default_image"
        fi
    fi

    # Generate the strict configuration file.
    local modsec_conf
    modsec_conf=$(generate_strict_modsec_conf)

    # Pull and run the container.
    echo "[INFO] Pulling Docker image: $image"
    sudo docker pull "$image"

    echo "[INFO] Running Dockerized ModSecurity container with strict settings..."
    sudo docker run -d --name dockerized_modsec -p 80:80 \
         -v "$modsec_conf":/etc/modsecurity/modsecurity.conf:ro \
         "$image"

    if sudo docker ps | grep -q dockerized_modsec; then
        echo "[*] Dockerized ModSecurity container 'dockerized_modsec' is running with strict configuration."
        return 0
    else
        echo "[X] Dockerized ModSecurity container failed to start."
        return 1
    fi
}

# Manual ModSecurity installation function (strict mode)
# This function is only available via the menu (not run by default).
function install_modsecurity_manual {
    print_banner "Manual ModSecurity Installation (Strict Mode)"
    local ipt
    ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)
    sudo $ipt -P OUTPUT ACCEPT
    if command -v yum &>/dev/null; then
        echo "RHEL-based manual ModSecurity installation not implemented"
    elif command -v apt-get &>/dev/null; then
        sudo apt-get update
        sudo apt-get -y install libapache2-mod-security2
        sudo a2enmod security2
        local strict_conf
        strict_conf=$(generate_strict_modsec_conf)
        sudo cp "$strict_conf" /etc/modsecurity/modsecurity.conf
        sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/g' /etc/modsecurity/modsecurity.conf
        sudo systemctl restart apache2
    elif command -v apk &>/dev/null; then
        echo "Alpine-based manual ModSecurity installation not implemented"
    else
        echo "Unsupported distribution for manual ModSecurity installation"
        exit 1
    fi
    sudo $ipt -P OUTPUT DROP
}



function remove_profiles {
    print_banner "Removing Profile Files"
    sudo mv /etc/prof{i,y}le.d /etc/profile.d.bak 2>/dev/null
    sudo mv /etc/prof{i,y}le /etc/profile.bak 2>/dev/null
    for f in ".profile" ".bashrc" ".bash_login"; do
        sudo find /home /root \( -path "/root/*" -o -path "/home/ccdcuser1/*" -o -path "/home/ccdcuser2/*" \) -prune -o -name "$f" -exec sudo rm {} \;
    done
}

function fix_pam {
    print_banner "Fixing PAM Configuration and Enforcing Password Policies"

    # Temporarily set iptables OUTPUT policy to ACCEPT.
    local ipt
    ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)
    sudo $ipt -P OUTPUT ACCEPT

    if grep -qi 'debian\|ubuntu' /etc/os-release; then
        echo "[*] Detected Debian/Ubuntu system; configuring PAM password policies."

        # Install libpam-pwquality if not already installed.
        sudo apt-get install -y libpam-pwquality

        # Update /etc/pam.d/common-password.
        local common_pass="/etc/pam.d/common-password"
        if [ -f "$common_pass" ]; then
            # Remove any existing password policy options.
            sudo sed -i 's/ minlen=[0-9]\+//g' "$common_pass"
            sudo sed -i 's/ retry=[0-9]\+//g' "$common_pass"
            sudo sed -i 's/ dcredit=[-0-9]\+//g' "$common_pass"
            sudo sed -i 's/ ucredit=[-0-9]\+//g' "$common_pass"
            sudo sed -i 's/ lcredit=[-0-9]\+//g' "$common_pass"
            sudo sed -i 's/ ocredit=[-0-9]\+//g' "$common_pass"
            sudo sed -i 's/ remember=[0-9]\+//g' "$common_pass"
            # Append the desired settings.
            sudo sed -i '/^password.*pam_unix\.so/ s/$/ minlen=12 retry=5 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 remember=5 sha512/' "$common_pass"
            echo "[*] Updated $common_pass with policy settings."
        else
            echo "[X] $common_pass not found."
        fi

        # Update /etc/login.defs for password aging.
        local login_defs="/etc/login.defs"
        if [ -f "$login_defs" ]; then
            sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   99999/' "$login_defs"
            sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   2/' "$login_defs"
            sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   10/' "$login_defs"
            echo "[*] Updated $login_defs with login definitions."
        else
            echo "[X] $login_defs not found."
        fi

    elif command -v yum >/dev/null; then
        if command -v authconfig >/dev/null; then
            sudo authconfig --updateall
            sudo yum -y reinstall pam
        else
            echo "[X] No authconfig found; cannot fix PAM on this system."
        fi
    elif command -v apk >/dev/null; then
        if [ -d /etc/pam.d ]; then
            sudo apk fix --purge linux-pam
            for file in $(find /etc/pam.d -name "*.apk-new" 2>/dev/null); do
                sudo mv "$file" "$(echo $file | sed 's/.apk-new//g')"
            done
        else
            echo "[X] PAM is not installed."
        fi
    elif command -v pacman >/dev/null; then
        if [ -n "$BACKUPDIR" ]; then
            sudo mv /etc/pam.d /etc/pam.d.backup
            sudo cp -R "$BACKUPDIR" /etc/pam.d
        else
            echo "[X] No backup directory provided for PAM configs."
        fi
        sudo pacman -S pam --noconfirm
    else
        echo "[X] Unknown OS; PAM configuration not fixed."
    fi

    # Restore iptables OUTPUT policy to DROP.
    sudo $ipt -P OUTPUT DROP
}


function search_ssn {
    print_banner "Searching for SSN Patterns"
    local rootdir="/home/"
    local ssn_pattern='[0-9]\{3\}-[0-9]\{2\}-[0-9]\{4\}'
    sudo find "$rootdir" -type f \( -name "*.txt" -o -name "*.csv" \) -exec sh -c '
        file="$1"
        pattern="$2"
        grep -Hn "$pattern" "$file" | while read -r line; do
            echo "$file:SSN:$line"
        done
    ' sh '{}' "$ssn_pattern" \;
}

function remove_unused_packages {
    print_banner "Removing Unused Packages"
    if command -v yum >/dev/null; then
        sudo yum purge -y -q netcat nc gcc cmake make telnet
    elif command -v apt-get >/dev/null; then
        sudo apt-get -y purge netcat nc gcc cmake make telnet
    elif command -v apk >/dev/null; then
        sudo apk remove gcc make
    else
        echo "Unsupported package manager for package removal"
    fi
}

function patch_vulnerabilities {
    print_banner "Patching Vulnerabilities"
    sudo chmod 0755 /usr/bin/pkexec
    sudo sysctl -w kernel.unprivileged_userns_clone=0
    echo "kernel.unprivileged_userns_clone = 0" | sudo tee -a /etc/sysctl.conf >/dev/null
    sudo sysctl -p >/dev/null
}

function check_permissions {
    print_banner "Checking and Setting Permissions"
    sudo chown root:root /etc/shadow
    sudo chown root:root /etc/passwd
    sudo chmod 640 /etc/shadow
    sudo chmod 644 /etc/passwd
    echo "[+] SUID binaries:"
    sudo find / -perm -4000 2>/dev/null
    echo "[+] Directories with 777 permissions (max depth 3):"
    sudo find / -maxdepth 3 -type d -perm -777 2>/dev/null
    echo "[+] Files with capabilities:"
    sudo getcap -r / 2>/dev/null
    echo "[+] Files with extended ACLs in critical directories:"
    sudo getfacl -sR /etc/ /usr/ /root/
}

function sysctl_config {
    print_banner "Applying sysctl Configurations"
    local file="/etc/sysctl.conf"
    echo "net.ipv4.tcp_syncookies = 1" | sudo tee -a "$file" >/dev/null
    echo "net.ipv4.tcp_synack_retries = 2" | sudo tee -a "$file" >/dev/null
    echo "net.ipv4.tcp_challenge_ack_limit = 1000000" | sudo tee -a "$file" >/dev/null
    echo "net.ipv4.tcp_rfc1337 = 1" | sudo tee -a "$file" >/dev/null
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" | sudo tee -a "$file" >/dev/null
    echo "net.ipv4.conf.all.accept_redirects = 0" | sudo tee -a "$file" >/dev/null
    echo "net.ipv4.icmp_echo_ignore_all = 1" | sudo tee -a "$file" >/dev/null
    echo "kernel.core_uses_pid = 1" | sudo tee -a "$file" >/dev/null
    echo "kernel.kptr_restrict = 2" | sudo tee -a "$file" >/dev/null
    echo "kernel.perf_event_paranoid = 2" | sudo tee -a "$file" >/dev/null
    echo "kernel.randomize_va_space = 2" | sudo tee -a "$file" >/dev/null
    echo "kernel.sysrq = 0" | sudo tee -a "$file" >/dev/null
    echo "kernel.yama.ptrace_scope = 2" | sudo tee -a "$file" >/dev/null
    echo "fs.protected_hardlinks = 1" | sudo tee -a "$file" >/dev/null
    echo "fs.protected_symlinks = 1" | sudo tee -a "$file" >/dev/null
    echo "fs.suid_dumpable = 0" | sudo tee -a "$file" >/dev/null
    echo "kernel.unprivileged_userns_clone = 0" | sudo tee -a "$file" >/dev/null
    echo "fs.protected_fifos = 2" | sudo tee -a "$file" >/dev/null
    echo "fs.protected_regular = 2" | sudo tee -a "$file" >/dev/null
    echo "kernel.kptr_restrict = 2" | sudo tee -a "$file" >/dev/null
    sudo sysctl -p >/dev/null
}

function my_secure_sql_installation {
    print_banner "My Secure SQL Installation"
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping mysql_secure_installation."
        return 0
    fi
    read -p "Would you like to run mysql_secure_installation? (y/N): " sql_choice
    if [[ "$sql_choice" == "y" || "$sql_choice" == "Y" ]]; then
         echo "[*] Running mysql_secure_installation..."
         sudo mysql_secure_installation
    else
         echo "[*] Skipping mysql_secure_installation."
    fi
}

function manage_web_immutability {
    print_banner "Manage Web Directory Immutability"
    if [ "$ANSIBLE" == "true" ]; then
         echo "[*] Ansible mode: Skipping immutable flag changes on web directories."
         return 0
    fi
    default_web_dirs=( "/etc/nginx" "/etc/apache2" "/usr/share/nginx" "/var/www" "/var/www/html" "/etc/lighttpd" "/etc/mysql" "/etc/postgresql" "/var/lib/apache2" "/var/lib/mysql" "/etc/redis" "/etc/phpMyAdmin" "/etc/php.d" )
    detected_web_dirs=()
    echo "[*] Scanning for critical web directories..."
    for dir in "${default_web_dirs[@]}"; do
        if [ -d "$dir" ]; then
            detected_web_dirs+=("$dir")
        fi
    done
    if [ ${#detected_web_dirs[@]} -eq 0 ]; then
        echo "[*] No critical web directories were found."
        return
    fi
    echo "[*] The following web directories have been detected:"
    for d in "${detected_web_dirs[@]}"; do
        echo "    $d"
    done
    read -p "Would you like to set these directories to immutable? (y/N): " imm_choice
    if [[ "$imm_choice" == "y" || "$imm_choice" == "Y" ]]; then
        for d in "${detected_web_dirs[@]}"; do
            sudo chattr +i "$d"
            echo "[*] Set immutable flag on $d"
        done
    else
        read -p "Would you like to remove the immutable flag from these directories? (y/N): " unimm_choice
        if [[ "$unimm_choice" == "y" || "$unimm_choice" == "Y" ]]; then
            for d in "${detected_web_dirs[@]}"; do
                sudo chattr -i "$d"
                echo "[*] Removed immutable flag from $d"
            done
        else
            echo "[*] No changes made to web directory immutability."
        fi
    fi
}


function kill_other_sessions {
    print_banner "Killing Non-Active Sessions"
    current_tty=$(tty | sed 's|/dev/||')
    echo "[*] Current session: $current_tty"
    other_ttys=$(who | awk -v ct="$current_tty" '$2 != ct {print $2}' | sort -u)
    if [ -n "$other_ttys" ]; then
        echo "[*] Killing sessions on ttys: $other_ttys"
        for tty in $other_ttys; do
            sudo pkill -KILL -t "$tty"
        done
    else
        echo "[*] No other sessions found."
    fi
}

function defend_against_forkbomb {
    print_banner "Defending Against Fork Bombing"
    # Create group 'fork' if it does not exist.
    if ! getent group fork >/dev/null; then
        sudo groupadd fork
        echo "[*] Group 'fork' created."
    else
        echo "[*] Group 'fork' already exists."
    fi

    # Get list of users with terminal access (shell in /bin/ or /usr/bin/)
    user_list=$(awk -F: '$1 != "root" && $7 ~ /^\/(bin|usr\/bin)\// { print $1 }' /etc/passwd)
    if [ -n "$user_list" ]; then
        for user in $user_list; do
            sudo usermod -a -G fork "$user"
            echo "[*] User $user added to group 'fork'."
        done
    else
        echo "[*] No applicable users found for fork protection."
    fi

    # Backup current limits.conf
    sudo cp /etc/security/limits.conf /etc/security/limits.conf.bak

    # Add process limits if not already present.
    if ! grep -q "^root hard" /etc/security/limits.conf; then
        echo "root hard nproc 1000" | sudo tee -a /etc/security/limits.conf >/dev/null
        echo "[*] Added 'root hard nproc 1000' to limits.conf."
    else
        echo "[*] Root nproc limit already set."
    fi

    if ! grep -q "^@fork hard" /etc/security/limits.conf; then
        echo "@fork hard nproc 300" | sudo tee -a /etc/security/limits.conf >/dev/null
        echo "[*] Added '@fork hard nproc 300' to limits.conf."
    else
        echo "[*] Fork group nproc limit already set."
    fi
}

function check_service_integrity {
    print_banner "Checking Service Binary Integrity"
    if grep -qi 'debian\|ubuntu' /etc/os-release; then
        # Ensure debsums is installed.
        if ! command -v debsums &>/dev/null; then
            echo "[*] Installing debsums..."
            sudo apt-get install -y debsums
        fi
        local packages=("apache2" "openssh-server" "mysql-server" "postfix" "nginx")
        for pkg in "${packages[@]}"; do
            if dpkg -s "$pkg" &>/dev/null; then
                echo "[*] Checking integrity for package: $pkg"
                # Run debsums and filter lines indicating failures.
                results=$(sudo debsums "$pkg" 2>/dev/null | grep "FAILED")
                if [ -n "$results" ]; then
                    echo "[WARNING] Integrity check FAILED for $pkg:"
                    echo "$results"
                else
                    echo "[*] $pkg passed integrity check."
                fi
            else
                echo "[*] Package $pkg is not installed; skipping."
            fi
        done
    elif grep -qi 'fedora\|centos\|rhel' /etc/os-release; then
        local packages=("httpd" "openssh" "mariadb-server" "postfix" "nginx")
        for pkg in "${packages[@]}"; do
            if rpm -q "$pkg" &>/dev/null; then
                echo "[*] Checking integrity for package: $pkg"
                results=$(rpm -V "$pkg")
                if [ -n "$results" ]; then
                    echo "[WARNING] Integrity check FAILED for $pkg:"
                    echo "$results"
                else
                    echo "[*] $pkg passed integrity check."
                fi
            else
                echo "[*] Package $pkg is not installed; skipping."
            fi
        done
    else
        echo "[X] Unsupported OS for native binary integrity checking."
    fi
}

function disable_phpmyadmin {
    print_banner "Disabling phpMyAdmin"

    # List of common phpMyAdmin directories
    local phpmyadmin_dirs=( "/etc/phpmyadmin" "/usr/share/phpmyadmin" "/var/www/phpmyadmin" "/var/www/html/phpmyadmin" "/usr/local/phpmyadmin" )
    for loc in "${phpmyadmin_dirs[@]}"; do
        if [ -d "$loc" ]; then
            sudo mv "$loc" "${loc}_disabled"
            echo "[*] Renamed directory $loc to ${loc}_disabled"
        fi
    done

    # List of common phpMyAdmin configuration files
    local phpmyadmin_configs=( "/etc/httpd/conf.d/phpMyAdmin.conf" "/etc/apache2/conf-enabled/phpmyadmin.conf" )
    for file in "${phpmyadmin_configs[@]}"; do
        if [ -f "$file" ]; then
            sudo mv "$file" "${file}.disabled"
            echo "[*] Renamed configuration file $file to ${file}.disabled"
        fi
    done
}

function fix_web_browser() {
    # Use provided directory (if any); default to Firefox's config directory
    local browser_dir="${1:-$HOME/.mozilla}"

    echo "=== Fixing Home Directory Permissions ==="
    # Reset home directory ownership and secure permissions.
    sudo chown -R "$(whoami):$(id -gn)" "$HOME"
    sudo chmod 700 "$HOME"
    echo "Home directory attributes:"
    lsattr -d "$HOME"

    if [ -d "$browser_dir" ]; then
        echo "=== Fixing Browser Configuration Directory: $browser_dir ==="
        echo "Current attributes for $browser_dir:"
        lsattr -d "$browser_dir"
        
        echo "Removing immutable flag from home directory..."
        sudo chattr -i "$HOME"
        echo "Removing immutable flag recursively from $browser_dir..."
        sudo chattr -R -i "$browser_dir"

        # Back up the existing browser configuration directory with a timestamp.
        local backup_dir="${browser_dir}_backup_$(date +%s)"
        echo "Backing up $browser_dir to $backup_dir..."
        mv "$browser_dir" "$backup_dir"

        echo "Creating new configuration directory at $browser_dir..."
        mkdir -p "$browser_dir"
    else
        echo "Browser configuration directory ($browser_dir) not found. Skipping browser-specific fixes."
    fi

    echo "=== Done ==="
}


function configure_apache_htaccess {
    print_banner "Configuring Apache .htaccess"
    # Ensure mod_rewrite is enabled (if available)
    if command -v a2enmod &> /dev/null; then
        sudo a2enmod rewrite
        sudo systemctl restart apache2
    fi
    # Determine the web root; defaults to /var/www/html if available, else /var/www
    if [ -d "/var/www/html" ]; then
         webroot="/var/www/html"
    elif [ -d "/var/www" ]; then
         webroot="/var/www"
    else
         echo "[X] No Apache web root found."
         return 1
    fi
    sudo bash -c "cat > ${webroot}/.htaccess" <<'EOF'
# Disable directory indexing
Options -Indexes

# Enable URL rewriting
RewriteEngine On
<IfModule mod_rewrite.c>
    # Block malicious user agents and specific scanning tools
    RewriteCond %{HTTP_USER_AGENT} ^w3af.sourceforge.net [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} dirbuster [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} nikto [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} SF [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} sqlmap [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} fimap [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} nessus [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} whatweb [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} Openvas [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} jbrofuzz [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} libwhisker [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} webshag [NC,OR]
    RewriteCond %{HTTP:Acunetix-Product} ^WVS [NC]
    RewriteRule ^.* http://127.0.0.1/ [R=301,L]
</IfModule>
EOF
    echo "[*] Apache .htaccess configured at ${webroot}/.htaccess"
}

function run_rkhunter {
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping Rootkit Hunter scan."
        return 0
    fi
    read -p "Would you like to run rkhunter (Rootkit Hunter) scan? (y/N): " run_rkh
    if [[ "$run_rkh" == "y" || "$run_rkh" == "Y" ]]; then
        print_banner "Running Rootkit Hunter"
        # Update package list and install rkhunter.
        sudo apt update
        sudo apt install -y rkhunter
        echo "[*] Running rkhunter scan. Please review the output for warnings."
        sudo rkhunter --check
    else
        echo "[*] Skipping rkhunter scan as per user decision."
    fi
}


function harden_web {
    print_banner "Web Hardening Initiated"
    backup_databases
    secure_php_ini
    # Use the Dockerized ModSecurity installation by default
    install_modsecurity_docker
    configure_apache_htaccess
    if [ "$ANSIBLE" == "true" ]; then
         echo "[*] Ansible mode: Skipping mysql_secure_installation and web directory immutability."
    else
         my_secure_sql_installation
         manage_web_immutability
    fi
}


##################### ADVANCED HARDENING FUNCTIONS #####################
function setup_iptables_cronjob {
    print_banner "Setting Up Iptables Persistence Cronjob"
    if grep -qi 'fedora\|centos\|rhel' /etc/os-release; then
        cron_file="/etc/cron.d/iptables_persistence"
        sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root /sbin/iptables-save > /etc/sysconfig/iptables
EOF
        echo "[*] Cron job created at $cron_file for RHEL-based systems."
    elif grep -qi 'debian\|ubuntu' /etc/os-release; then
        cron_file="/etc/cron.d/iptables_persistence"
        sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root /sbin/iptables-save > /etc/iptables/rules.v4
EOF
        echo "[*] Cron job created at $cron_file for Debian-based systems."
    else
        echo "[*] Unknown OS. Please set up a cron job manually for iptables persistence."
    fi
}

function disable_unnecessary_services {
    print_banner "Disabling Unnecessary Services"
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping disabling services."
        return 0
    fi
    read -p "Disable SSHD? (WARNING: may lock you out if remote) (y/N): " disable_sshd
    if [[ "$disable_sshd" =~ ^[Yy]$ ]]; then
        if systemctl is-active sshd &> /dev/null; then
            sudo systemctl stop sshd
            sudo systemctl disable sshd
            echo "[*] SSHD service disabled."
        else
            echo "[*] SSHD service not active."
        fi
    fi
    read -p "Disable Cockpit? (y/N): " disable_cockpit
    if [[ "$disable_cockpit" =~ ^[Yy]$ ]]; then
        if systemctl is-active cockpit &> /dev/null; then
            sudo systemctl stop cockpit
            sudo systemctl disable cockpit
            echo "[*] Cockpit service disabled."
        else
            echo "[*] Cockpit service not active."
        fi
    fi
}

function setup_firewall_maintenance_cronjob_iptables {
    print_banner "Setting Up iptables Maintenance Cronjob"
    local script_file="/usr/local/sbin/firewall_maintain.sh"
    sudo bash -c "cat > $script_file" <<'EOF'
#!/bin/bash
open_ports=$(ss -lnt | awk 'NR>1 {split($4,a,":"); print a[length(a)]}' | sort -nu)
for port in $open_ports; do
    iptables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport $port -j ACCEPT
done
EOF
    sudo chmod +x "$script_file"
    local cron_file="/etc/cron.d/firewall_maintenance"
    sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root $script_file
EOF
    echo "[*] iptables maintenance cron job created."
}

function setup_firewall_maintenance_cronjob_ufw {
    print_banner "Setting Up UFW Maintenance Cronjob"
    backup_current_ufw_rules
    local script_file="/usr/local/sbin/ufw_maintain.sh"
    sudo bash -c "cat > $script_file" <<'EOF'
#!/bin/bash
if [ -f /tmp/ufw_backup.rules ]; then
    ufw reset
    cp /tmp/ufw_backup.rules /etc/ufw/user.rules
    ufw reload
fi
EOF
    sudo chmod +x "$script_file"
    local cron_file="/etc/cron.d/ufw_maintenance"
    sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root /usr/local/sbin/ufw_maintain.sh
EOF
    echo "[*] UFW maintenance cron job created."
}

function setup_firewall_maintenance_cronjob {
    if command -v ufw &>/dev/null && sudo ufw status | grep -q "Status: active"; then
        setup_firewall_maintenance_cronjob_ufw
    else
        setup_firewall_maintenance_cronjob_iptables
    fi
}

function setup_nat_clear_cronjob {
    print_banner "Setting Up NAT Table Clear Cronjob"
    cron_file="/etc/cron.d/clear_nat_table"
    sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root /sbin/iptables -t nat -F
EOF
    echo "[*] NAT table clear cron job created."
}

function setup_service_restart_cronjob {
    print_banner "Setting Up Service Restart Cronjob"
    detected_service=""
    if command -v ufw &>/dev/null && sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        detected_service="ufw"
    elif systemctl is-active firewalld &>/dev/null; then
        detected_service="firewalld"
    elif systemctl is-active netfilter-persistent &>/dev/null; then
        detected_service="netfilter-persistent"
    else
        echo "[*] No recognized firewall service detected automatically."
    fi
    if [ -n "$detected_service" ]; then
        echo "[*] Detected firewall service: $detected_service"
        local script_file="/usr/local/sbin/restart_${detected_service}.sh"
        sudo bash -c "cat > $script_file" <<EOF
#!/bin/bash
systemctl restart $detected_service
EOF
        sudo chmod +x $script_file
        local cron_file="/etc/cron.d/restart_${detected_service}"
        sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root $script_file
EOF
        echo "[*] Cron job created to restart $detected_service every 5 minutes."
    fi
    if [ "$ANSIBLE" != "true" ]; then
        read -p "Would you like to add additional services to restart via cronjob? (y/N): " add_extra
        if [[ "$add_extra" =~ ^[Yy]$ ]]; then
            while true; do
                read -p "Enter the name of the additional service (or leave blank to finish): " extra_service
                if [ -z "$extra_service" ]; then
                    break
                fi
                local extra_script_file="/usr/local/sbin/restart_${extra_service}.sh"
                sudo bash -c "cat > $extra_script_file" <<EOF
#!/bin/bash
systemctl restart $extra_service
EOF
                sudo chmod +x $extra_script_file
                local extra_cron_file="/etc/cron.d/restart_${extra_service}"
                sudo bash -c "cat > $extra_cron_file" <<EOF
*/5 * * * * root $extra_script_file
EOF
                echo "[*] Cron job created to restart $extra_service every 5 minutes."
            done
        fi
    else
        echo "[*] Ansible mode: Skipping additional service restart configuration."
    fi
    echo "[*] Service restart configuration complete."
}

function reset_advanced_hardening {
    print_banner "Resetting Advanced Hardening Configurations"
    echo "[*] Removing iptables persistence cronjob (if exists)..."
    sudo rm -f /etc/cron.d/iptables_persistence
    echo "[*] Removing firewall maintenance cronjob and script..."
    sudo rm -f /etc/cron.d/firewall_maintenance
    sudo rm -f /usr/local/sbin/firewall_maintain.sh
    echo "[*] Removing NAT table clear cronjob..."
    sudo rm -f /etc/cron.d/clear_nat_table
    echo "[*] Removing service restart cronjobs and scripts..."
    sudo rm -f /etc/cron.d/restart_*
    sudo rm -f /usr/local/sbin/restart_*
    echo "[*] Advanced hardening configurations have been reset."
}

function run_full_advanced_hardening {
    print_banner "Running Full Advanced Hardening Process"
    setup_iptables_cronjob
    disable_unnecessary_services
    setup_firewall_maintenance_cronjob
    setup_nat_clear_cronjob
    setup_service_restart_cronjob
    echo "[*] Full Advanced Hardening Process Completed."
}

function advanced_hardening {
    if [ "$ANSIBLE" == "true" ]; then
         echo "[*] Ansible mode: Skipping advanced hardening prompts."
         return 0
    fi
    local adv_choice
    while true; do
        print_banner "Advanced Hardening & Automation #TESTING, JUST PLACEHOLDERS"
        echo "1) Run Full Advanced Hardening Process"
        echo "2) Set up iptables persistence cronjob"
        echo "3) Disable SSHD/Cockpit services"
        echo "4) Set up firewall maintenance cronjob (monitor open ports)"
        echo "5) Set up cronjob to clear NAT table"
        echo "6) Set up cronjob to restart firewall service and additional services"
        echo "7) Reset Advanced Hardening Configurations"
        echo "8) Run rkhunter scan"
        echo "9) Check Service Integrity"
        echo "10) Fix Web Browser Permissions"
        echo "11) Exit Advanced Hardening Menu"
        read -p "Enter your choice [1-11]: " adv_choice
        case $adv_choice in
            1) run_full_advanced_hardening ;;
            2) setup_iptables_cronjob ;;
            3) disable_unnecessary_services ;;
            4) setup_firewall_maintenance_cronjob ;;
            5) setup_nat_clear_cronjob ;;
            6) setup_service_restart_cronjob ;;
            7) reset_advanced_hardening ;;
            8) run_rkhunter ;;
            9) check_service_integrity ;;
            10) fix_web_browser ;;
            11) echo "[*] Exiting advanced hardening menu."; break ;;
            *) echo "[X] Invalid option." ;;
        esac
        echo ""
    done
}




##################### WEB HARDENING MENU FUNCTION #####################
function show_web_hardening_menu {
    print_banner "Web Hardening Menu"
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Running full web hardening non-interactively."
        harden_web
        disable_phpmyadmin
        return 0
    fi
    echo "1) Run Full Web Hardening Process"
    echo "2) backup_databases"
    echo "3) secure_php_ini"
    echo "4) Install ModSecurity (Dockerized) [Default]"
    echo "5) Install ModSecurity (Manual)"
    echo "6) my_secure_sql_installation"
    echo "7) manage_web_immutability"
    echo "8) Disable phpMyAdmin"
    echo "9) Exit Web Hardening Menu"
    read -p "Enter your choice [1-9]: " web_menu_choice
    case $web_menu_choice in
        1)
            print_banner "Web Hardening Initiated"
            backup_databases
            secure_php_ini
            install_modsecurity_docker
            my_secure_sql_installation
            manage_web_immutability
            ;;
        2)
            print_banner "Web Hardening Initiated"
            backup_databases
            ;;
        3)
            print_banner "Web Hardening Initiated"
            secure_php_ini
            ;;
        4)
            print_banner "Web Hardening Initiated (Dockerized ModSecurity)"
            install_modsecurity_docker
            ;;
        5)
            print_banner "Web Hardening Initiated (Manual ModSecurity)"
            install_modsecurity_manual
            ;;
        6)
            print_banner "Web Hardening Initiated"
            my_secure_sql_installation
            ;;
        7)
            print_banner "Web Hardening Initiated"
            manage_web_immutability
            ;;
        8)
            print_banner "Disabling phpMyAdmin"
            disable_phpmyadmin
            ;;
        9)
            echo "[*] Exiting Web Hardening Menu"
            ;;
        *)
            echo "[X] Invalid option."
            ;;
    esac
}


##################### MAIN MENU FUNCTION #####################
function show_menu {
    print_banner "Hardening Script Menu"
    echo "1) Full Hardening Process (Run all)"
    echo "2) User Management"
    echo "3) Firewall Configuration"
    echo "4) Backup"
    echo "5) Splunk Installation"
    echo "6) SSH Hardening"
    echo "7) PAM/Profile Fixes & System Config"
    echo "8) Web Hardening"
    echo "9) Advanced Hardening"
    echo "10) Exit"
    echo
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
        3)
            firewall_configuration_menu
            ;;
        4)
            backups
            ;;
        5)
            setup_splunk
            ;;
        6)
            secure_ssh
            ;;
        7)
            fix_pam
            remove_profiles
            check_permissions
            sysctl_config
            ;;
        8)
            show_web_hardening_menu
            ;;
        9)
            advanced_hardening
            ;;
        10)
            echo "Exiting..."; exit 0
            ;;
        *)
            echo "Invalid option. Exiting."; exit 1
            ;;
    esac
}

##################### MAIN FUNCTION #####################
function main {
    kill_other_sessions
    echo "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    echo "[*] Start of full hardening process"
    detect_system_info
    install_prereqs
    create_ccdc_users
    change_passwords
    disable_users
    remove_sudoers
    audit_running_services
    disable_other_firewalls
    firewall_configuration_menu
    if [ "$ANSIBLE" != "true" ]; then
         backups
    else
         echo "[*] Ansible mode: Skipping backup section."
    fi
    if [ "$ANSIBLE" == "true" ]; then
         echo "[*] Ansible mode: Skipping Splunk installation."
    else
         setup_splunk
    fi
    secure_ssh
    remove_profiles
    fix_pam
    search_ssn
    remove_unused_packages
    patch_vulnerabilities
    check_permissions
    sysctl_config
    configure_login_banner
    defend_against_forkbomb

    # Disable phpMyAdmin by default for both Ansible and non-interactive execution.
    disable_phpmyadmin

    if [ "$ANSIBLE" != "true" ]; then
         web_choice=$(get_input_string "Would you like to perform web hardening? (y/N): ")
         if [ "$web_choice" == "y" ]; then
             show_web_hardening_menu
         fi
         adv_choice=$(get_input_string "Would you like to perform advanced hardening? (y/N): ")
         if [ "$adv_choice" == "y" ]; then
             advanced_hardening
         fi
    else
         echo "[*] Ansible mode: Running web hardening non-interactively."
         harden_web
         echo "[*] Ansible mode: Skipping advanced hardening prompts."
    fi
    run_rkhunter
    check_service_integrity
    echo "[*] End of full hardening process"
    echo "[*] Script log can be viewed at $LOG"
    echo "[*][WARNING] FORWARD chain is set to DROP. If this box is a router or network device, please run 'sudo iptables -P FORWARD ALLOW'."
    echo "[*] ***Please install system updates now***"
}





##################### ARGUMENT PARSING + LOGGING SETUP #####################
for arg in "$@"; do
    case "$arg" in
        --debug )
            echo "[*] Debug mode enabled"
            debug="true"
            ;;
        -ansible )
            echo "[*] Ansible mode enabled: Skipping interactive prompts."
            ANSIBLE="true"
            ;;
    esac
done

LOG_PATH=$(dirname "$LOG")
if [ ! -d "$LOG_PATH" ]; then
    sudo mkdir -p "$LOG_PATH"
    sudo chown root:root "$LOG_PATH"
    sudo chmod 750 "$LOG_PATH"
fi

##################### MAIN EXECUTION #####################
if [ "$ANSIBLE" == "true" ]; then
    main
else
    show_menu
fi
