#!/bin/bash
# Usage: ./harden.sh [option]

###################### GLOBALS ######################
LOG='/var/log/ccdc/harden.log'
GITHUB_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/refs/heads/main"
pm=""
sudo_group=""
ccdc_users=( "ccdcuser1" "ccdcuser2" )
debug="false"
#####################################################

##################### FUNCTIONS #####################
# Prints text in a banner
# Arguments:
#   $1: Text to print
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
    read -r -p "$1" input
    echo "$input"
}

function get_silent_input_string {
    read -r -s -p "$1" input
    echo "$input"
}

function get_input_list {
    local input_list=()

    while [ "$continue" != "false" ]; do
        input=$(get_input_string "Enter input: (one entry per line; hit enter to continue): ")
        if [ "$input" == "" ]; then
            continue="false"
        else
            input_list+=("$input")
        fi
    done

    # Return the list by printing it
    # Note: Bash functions can't return arrays directly, but we can print them
    echo "${input_list[@]}"
}

function exclude_users {
    users="$@"
    input=$(get_input_list)
    for item in $input; do
        users+=("$item")
    done
    echo "${users[@]}"
}

function get_users {
    awk_string=$1
    exclude_users=$(sed -e 's/ /\\|/g' <<< $2)
    users=$(awk -F ':' "$awk_string" /etc/passwd)
    filtered=$(echo "$users" | grep -v -e $exclude_users)
    readarray -t results <<< $filtered
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
    # TODO: install a syslog daemon for Splunk?
    # Needed for both hardening and Splunk installation
    sudo $pm install -y zip unzip wget curl acl
}

function create_ccdc_users {
    print_banner "Creating ccdc users"
    for user in "${ccdc_users[@]}"; do
        if id "$user" &>/dev/null; then
            echo "[*] $user already exists. Skipping..."
        else
            echo "[*] $user not found. Attempting to create..."
            if [ -f "/bin/bash" ]; then
                sudo useradd -m -s /bin/bash "$user"
            elif [ -f "/bin/sh" ]; then
                sudo useradd -m -s /bin/sh "$user"
            else
                echo "[X] ERROR: Could not find valid shell"
                exit 1
            fi
            
            echo "[*] Enter the new password for $user:"
            while true; do
                password=""
                confirm_password=""

                # Ask for password
                password=$(get_silent_input_string "Enter password: ")
                echo

                # Confirm password
                confirm_password=$(get_silent_input_string "Confirm password: ")
                echo

                if [ "$password" != "$confirm_password" ]; then
                    echo "Passwords do not match. Please retry."
                    continue
                fi

                if ! echo "$user:$password" | sudo chpasswd; then
                    echo "[X] ERROR: Failed to set password for $user"
                else
                    echo "[*] Password for $user has been set."
                    break
                fi
            done

            if [ "$user" == "ccdcuser1" ]; then
                echo "[*] Adding to $sudo_group group"
                sudo usermod -aG $sudo_group "$user"
            fi
        fi
        echo
    done
}

function change_passwords {
    print_banner "Changing user passwords"

    exclusions=("${ccdc_users[@]}")
    echo "[*] Currently excluded users: ${exclusions[*]}"
    echo "[*] Would you like to exclude any additional users?"
    option=$(get_input_string "(y/N): ")
    if [ "$option" == "y" ]; then
        exclusions=$(exclude_users "${exclusions[@]}")
    fi

    # if sudo [ -e "/etc/centos-release" ] ; then
    #     # CentOS starts numbering at 500
    #     targets=$(get_users '$3 >= 500 && $1 != "nobody" {print $1}' "${exclusions[*]}")
    # else
    #     # Otherwise 1000
    #     targets=$(get_users '$3 >= 1000 && $1 != "nobody" {print $1}' "${exclusions[*]}")
    # fi
    targets=$(get_users '$1 != "nobody" {print $1}' "${exclusions[*]}")

    echo "[*] Enter the new password to be used for all users."
    while true; do
        password=""
        confirm_password=""

        # Ask for password
        password=$(get_silent_input_string "Enter password: ")
        echo

        # Confirm password
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
    print_banner "Disabling users"

    nologin_shell=""
    if [ -f /usr/sbin/nologin ]; then
        nologin_shell="/usr/sbin/nologin"
    elif [ -f /sbin/nologin ]; then
        nologin_shell="/sbin/nologin"
    else
        nologin_shell="/bin/false"
    fi

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

    echo "[*] Disabling users..."
    for user in $targets; do
        sudo usermod -s "$nologin_shell" "$user"
        echo "[*] Set shell for $user to $nologin_shell"
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

function disable_other_firewalls {
    print_banner "Disabling existing firewalls"
    if sudo command -v firewalld &>/dev/null; then
        echo "[*] disabling firewalld"
        sudo systemctl stop firewalld
        sudo systemctl disable firewalld
    fi
    # elif sudo command -v ufw &>/dev/null; then
    #     echo "[*] disabling ufw"
    #     sudo ufw disable
    # fi

    # Some systems may also have iptables as backend
    # if sudo command -v iptables &>/dev/null; then
    #     echo "[*] clearing iptables rules"
    #     sudo iptables -F
    # fi
}

function setup_ufw {
    print_banner "Configuring ufw"

    sudo $pm install -y ufw
    sudo which ufw &> /dev/null
    if [ $? == 0 ]; then
        echo -e "[*] Package ufw installed successfully\n"
        echo "[*] Which ports should be opened for incoming traffic?"
        echo "      WARNING: Do NOT forget to add 22/SSH if needed- please don't accidentally lock yourself out of the system!"
        sudo ufw --force disable
        sudo ufw --force reset
        ports=$(get_input_list)
        for port in $ports; do
            sudo ufw allow "$port"
            echo "[*] Rule added for port $port"
        done
        sudo ufw logging on
        sudo ufw --force enable
    else
        echo "[X] ERROR: Package ufw failed to install. Firewall will need to be configured manually"
    fi
}

function setup_iptables {
    # TODO: this needs work/testing on different distros
    print_banner "Configuring iptables"
    echo "[*] Installing iptables packages"

    if [ "$pm" == 'apt' ]; then
        # Debian and Ubuntu
        sudo "$pm" install -y iptables iptables-persistent #ipset
        SAVE='/etc/iptables/rules.v4'
    else
        # Fedora
        sudo "$pm" install -y iptables-services
        sudo systemctl enable iptables
        sudo systemctl start iptables
        SAVE='/etc/sysconfig/iptables'
    fi

    # echo "[*] Creating private ip range ipset"
    # sudo ipset create PRIVATE-IP hash:net
    # sudo ipset add PRIVATE-IP 10.0.0.0/8
    # sudo ipset add PRIVATE-IP 172.16.0.0/12
    # sudo ipset add PRIVATE-IP 192.168.0.0/16
    # sudo ipset save | sudo tee /etc/ipset.conf
    # sudo systemctl enable ipset

    echo "[*] Creating INPUT rules"
    sudo iptables -P INPUT DROP
    sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A INPUT -s 0.0.0.0/0 -j ACCEPT

    echo "[*] Which ports should be open for incoming traffic (INPUT)?"
    echo "[*] Warning: Do NOT forget to add 22/SSH if needed- please don't accidentally lock yourself out of the system!"
    ports=$(get_input_list)
    for port in $ports; do
        sudo iptables -A INPUT --dport "$port" -j ACCEPT
    done
    # TODO: is there a better alternative to this rule?
    sudo iptables -A INPUT -j LOG --log-prefix "[iptables] CHAIN=INPUT ACTION=DROP "

    echo "[*] Creating OUTPUT rules"
    # TODO: harden this as much as possible, like by limiting destination hosts
    # sudo iptables -P OUTPUT DROP
    # sudo iptables -A OUTPUT -o lo -j ACCEPT
    # sudo iptables -A OUTPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set PRIVATE-IP dst -j ACCEPT
    # Web traffic
    sudo iptables -A OUTPUT -p tcp -m multiport --dport 80,443 -j WEB
    sudo iptables -N WEB
    sudo iptables -A WEB -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -j LOG --log-prefix "[iptables] WEB/private ip "
    sudo iptables -A WEB -j ACCEPT
    # DNS traffic
    sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

    echo "[*] Saving rules"
    sudo iptables-save | sudo tee $SAVE
}

function backups {
    print_banner "Backups"
    echo "[*] Would you like to backup any files?"
    option=$(get_input_string "(y/N): ")

    if [ "$option" != "y" ]; then
        return
    fi
    
    # Enter directories to backup
    repeat=true
    while $repeat; do
        repeat=false
        dirs_to_backup=()
        echo "Enter directories/files to backup:"
        input=$(get_input_list)
        for item in $input; do
            path=$(readlink -f "$item")
            if sudo [ -e "$path" ]; then
                dirs_to_backup+=("$path")
            else
                echo "[X] ERROR: $path is invalid or does not exist"
                repeat=true
            fi
        done
    done

    # Get backup storage name
    while true; do
        backup_name=$(get_input_string "Enter name for encrypted backups file (ex. cosmo.zip ): ")
        if [ "$backup_name" != "" ]; then
            break
        fi
        echo "[X] ERROR: Backup name cannot be blank"
    done
    # Get backup storage location
    while true; do
        backup_dir=$(get_input_string "Enter directory to place encrypted backups file (ex. /var/log/ ): ")
        backup_dir=$(readlink -f "$backup_dir")
        if sudo [ -e "$backup_dir" ]; then
            break
        fi
        echo "[X] ERROR: $backup_dir is invalid or does not exist"
    done
    # Get backup encryption password
    echo "[*] Enter the backup encryption password."
    while true; do
        password=""
        confirm_password=""

        # Ask for password
        password=$(get_silent_input_string "Enter password: ")
        echo

        # Confirm password
        confirm_password=$(get_silent_input_string "Confirm password: ")
        echo

        if [ "$password" != "$confirm_password" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done

    # Zip all directories and store in backups directory
    sudo mkdir "$backup_dir/backups"
    for dir in "${dirs_to_backup[@]}"; do
        filename=$(basename "$dir")
        sudo zip -r "$backup_dir/backups/$filename.zip" "$dir" &> /dev/null
    done

    # Compress backups directory
    tar -czvf "$backup_dir/backups.tar.gz" -C "$backup_dir" backups &>/dev/null

    # Encrypt backup
    openssl enc -aes-256-cbc -salt -in "$backup_dir/backups.tar.gz" -out "$backup_dir/$backup_name" -k "$password"
    
    # Double check that backup exists before deleting intermediary files
    if sudo [ -e "$backup_dir/$backup_name" ]; then
        sudo rm "$backup_dir/backups.tar.gz"
        sudo rm -rf "$backup_dir/backups"
        echo "[*] Backups successfully stored and encrypted."
    else
        echo "[X] ERROR: Could not successfully create backups."
    fi
}

function setup_splunk {
    print_banner "Installing Splunk"
    indexer_ip=$(get_input_string "What is the Splunk forward server ip? ")

    wget $GITHUB_URL/splunk/splunk.sh --no-check-certificate
    chmod +x splunk.sh
    ./splunk.sh -f $indexer_ip
}


##################### ADDITIONAL WEB HARDENING FUNCTIONS #####################

function backup_databases {
    print_banner "Hardening Databases"
    # Check if MySQL/MariaDB is active and if default (empty) root login works.
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

    # Check if PostgreSQL is active
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

function secure_ssh {
    print_banner "Securing SSH"
    if sudo service sshd status > /dev/null; then
        # Enable root login and disable public-key authentication for root
        sudo sed -i '1s;^;PermitRootLogin yes\n;' /etc/ssh/sshd_config
        sudo sed -i '1s;^;PubkeyAuthentication no\n;' /etc/ssh/sshd_config

        # For non-RedHat systems, disable PAM in sshd_config
        if ! grep -qi "REDHAT_" /etc/os-release; then
            sudo sed -i '1s;^;UsePAM no\n;' /etc/ssh/sshd_config
        fi

        sudo sed -i '1s;^;UseDNS no\n;' /etc/ssh/sshd_config
        sudo sed -i '1s;^;PermitEmptyPasswords no\n;' /etc/ssh/sshd_config
        sudo sed -i '1s;^;AddressFamily inet\n;' /etc/ssh/sshd_config
        sudo sed -i '1s;^;Banner none\n;' /etc/ssh/sshd_config

        # Restart the SSH service if the configuration tests out
        sudo sshd -t && sudo systemctl restart sshd
    fi
}

function install_modsecurity {
    print_banner "Installing ModSecurity"
    local ipt
    ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)
    sudo $ipt -P OUTPUT ACCEPT

    if command -v yum >/dev/null; then
        # RHEL-based systems (not implemented in this snippet)
        echo "RHEL-based ModSecurity installation not implemented"
    elif command -v apt-get >/dev/null; then
        # Debian/Ubuntu (and other Debian-based) systems
        sudo apt-get update
        sudo apt-get -y install libapache2-mod-security2
        sudo a2enmod security2
        sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
        sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/g' /etc/modsecurity/modsecurity.conf
        sudo systemctl restart apache2
    elif command -v apk >/dev/null; then
        # Alpine-based systems (not implemented in this snippet)
        echo "Alpine-based ModSecurity installation not implemented"
    else
        echo "Unsupported distribution for ModSecurity installation"
        exit 1
    fi

    sudo $ipt -P OUTPUT DROP
}

function remove_profiles {
    print_banner "Removing Profile Files"
    sudo mv /etc/prof{i,y}le.d 2>/dev/null
    sudo mv /etc/prof{i,y}le 2>/dev/null
    for f in ".profile" ".bashrc" ".bash_login"; do
        find /home /root -name "$f" -exec sudo rm {} \;
    done
}

function fix_pam {
    print_banner "Fixing PAM Configuration"
    local ipt
    ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)
    sudo $ipt -P OUTPUT ACCEPT

    if command -v yum >/dev/null; then
        if command -v authconfig >/dev/null; then
            sudo authconfig --updateall
            sudo yum -y reinstall pam
        else
            echo "No authconfig, cannot fix PAM on this system"
        fi
    elif command -v apt-get >/dev/null; then
        sudo DEBIAN_FRONTEND=noninteractive pam-auth-update --force
        sudo apt-get -y --reinstall install libpam-runtime libpam-modules
    elif command -v apk >/dev/null; then
        if [ -d /etc/pam.d ]; then
            sudo apk fix --purge linux-pam
            for file in $(find /etc/pam.d -name "*.apk-new" 2>/dev/null); do
                sudo mv "$file" "$(echo $file | sed 's/.apk-new//g')"
            done
        else
            echo "PAM is not installed"
        fi
    elif command -v pacman >/dev/null; then
        if [ -z "$BACKUPDIR" ]; then
            echo "No backup directory provided for PAM configs"
        else
            sudo mv /etc/pam.d /etc/pam.d.backup
            sudo cp -R "$BACKUPDIR" /etc/pam.d
        fi
        sudo pacman -S pam --noconfirm
    else
        echo "Unknown OS, not fixing PAM"
    fi

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
    # Patch pwnkit vulnerability
    sudo chmod 0755 /usr/bin/pkexec

    # Patch CVE-2023-32233 vulnerability
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

function harden_web {
    print_banner "Web Hardening Initiated"
    backup_databases
    secure_php_ini
    install_modsecurity
    # Additional user security measures (e.g., auditing hidden users) can be added here.
}

######################## MAIN #######################
function main {
    echo "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    echo "[*] Start of script"

    detect_system_info
    install_prereqs

    create_ccdc_users
    change_passwords
    disable_users
    remove_sudoers

    disable_other_firewalls
    setup_ufw
    # setup_iptables

    backups
    setup_splunk
        
	
    # updates below: 
    secure_ssh
    remove_profiles
    fix_pam
    search_ssn
    remove_unused_packages
    patch_vulnerabilities
    check_permissions
    sysctl_config

    echo "[*] End of script"
    echo "[*] Script log can be viewed at $LOG"
    echo "[*] ***Please install system updates now***"
}

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --debug )
            echo "[*] Debug mode enabled"
            debug="true"
        ;;
    esac
done

# Set up logging
LOG_PATH=$(dirname "$LOG")
if [ ! -d "$LOG_PATH" ]; then
    sudo mkdir -p "$LOG_PATH"
    sudo chown root:root "$LOG_PATH"
    sudo chmod 750 "$LOG_PATH"
fi

# Run main function and log output
main "$@" 2>&1 | sudo tee -a $LOG

# After main, prompt the user whether to perform web hardening.
web_choice=$(get_input_string "Would you like to harden web? (y/N): ")
if [ "$web_choice" == "y" ]; then
    harden_web
fi
