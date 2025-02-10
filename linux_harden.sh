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
    # Needed for both hardening and Splunk installlation
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

########################################################################
# FUNCTION: setup_ufw
# Configures UFW firewall rules.
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

########################################################################
# FUNCTION: setup_custom_iptables
# This function writes the entire custom IPtables/awk script 
# to a temporary file, executes it, and then prompts the user to add additional
# manual port-based rules.
function setup_custom_iptables {
    print_banner "Configuring iptables (Custom Script)"
    tmpfile=$(mktemp /tmp/iptables_script.XXXXXX)
    cat <<'EOF' > "$tmpfile"
#!/bin/bash
# Below is a dual-mode script that is both valid Bash and AWK.
#region bash
sh -c "ss -napH4 | awk -f $BASH_SOURCE" {0..0}
"exit" {0..0}
#endregion bash

# This AWK section sets configuration parameters and builds an iptables ruleset.
BEGIN {
  UNRESTRICTED_SUBNETS = "10.128.XXX.0/24";
  EXTERNAL_SUBNET = "10.120.XXX.0/24";  # UNUSED
  DNS_SERVERS = "192.168.XXX.1 192.168.XXX.2";
  IPTABLES_CMD = "iptables";
  DEFAULT_INPUT_CHAIN = "INPUT";
  DEFAULT_OUTPUT_CHAIN = "OUTPUT";
  LOG_LEVEL = 2;
  SKIP_PROMPT = 0;
  INBOUND_CONNECTION_TYPES = "LISTEN";
  OUTBOUND_CONNECTION_TYPES = "ESTAB";
  INBOUND_PORT_WHITELIST  = "21 22 80 443 53";
  OUTBOUND_PORT_WHITELIST = INBOUND_PORT_WHITELIST;
  COLORED_OUTPUT = 1;
}

function keyify(arr) {
  for(i in arr) arr[arr[i]] = 1;
}

BEGIN {
  split(INBOUND_CONNECTION_TYPES, INBOUND_CONNECTION_TYPES_ARRAY);
  keyify(INBOUND_CONNECTION_TYPES_ARRAY);
  split(OUTBOUND_CONNECTION_TYPES, OUTBOUND_CONNECTION_TYPES_ARRAY);
  keyify(OUTBOUND_CONNECTION_TYPES_ARRAY);
  split(INBOUND_PORT_WHITELIST, INBOUND_PORT_WHITELIST_ARRAY);
  keyify(INBOUND_PORT_WHITELIST_ARRAY);
  split(OUTBOUND_PORT_WHITELIST, OUTBOUND_PORT_WHITELIST_ARRAY);
  keyify(OUTBOUND_PORT_WHITELIST_ARRAY);
  delete COLORS[0];
  COLORS["black"]         = 30;
  COLORS["red"]           = 31;
  COLORS["green"]         = 32;
  COLORS["yellow"]        = 33;
  COLORS["blue"]          = 34;
  COLORS["magenta"]       = 35;
  COLORS["cyan"]          = 36;
  COLORS["white"]         = 37;
  COLORS["default"]       = 39;
  COLORS["gray"]          = 90;
  COLORS["brightRed"]     = 91;
  COLORS["brightGreen"]   = 92;
  COLORS["brightYellow"]  = 93;
  COLORS["brightBlue"]    = 94;
  COLORS["brightMagenta"] = 95;
  COLORS["brightCyan"]    = 96;
  COLORS["brightWhite"]   = 97;
  delete LOG_LEVEL_COLORS[0];
  LOG_LEVEL_COLORS["DEBUG"]   = "magenta";
  LOG_LEVEL_COLORS["INFO"]    = "cyan";
  LOG_LEVEL_COLORS["WARNING"] = "yellow";
  LOG_LEVEL_COLORS["ERROR"]   = "red";
  delete LOG_LEVEL_NAMES[0];
  LOG_LEVEL_NAMES["DEBUG"]   = 1;
  LOG_LEVEL_NAMES["INFO"]    = 2;
  LOG_LEVEL_NAMES["WARNING"] = 3;
  LOG_LEVEL_NAMES["ERROR"]   = 4;
}

function setColor(color) {
  if(!COLORED_OUTPUT)
    return "";
  else if(color == "")
    return "\033[39m";
  else
    return sprintf("\033[%dm", COLORS[color]);
}

function colored(color, message) {
  return setColor(color) message setColor();
}

function printLog(level, message) {
  if(LOG_LEVEL_NAMES[level] < LOG_LEVEL) return;
  printf("%*s: %s\n", COLORED_OUTPUT ? 17 : 7, colored(LOG_LEVEL_COLORS[level], level), message) > "/dev/tty";
}

function formatPort(port, proto, name) {
  return colored("yellow", sprintf("%5d", port)) "/" proto " (" colored("blue", name) ")";
}

BEGIN {
  "tty" | getline isTTY;
  if(isTTY != "not a tty")
    printLog("WARNING", "TTY stdin detected. This script is designed to take the output from `ss -napOH4`");
  if(!SKIP_PROMPT) {
    print(colored("red", "WARNING") ": Existing rules for the " DEFAULT_INPUT_CHAIN " and " DEFAULT_OUTPUT_CHAIN " chains will be flushed!\nPress RETURN to continue.") > "/dev/tty";
    getline < "/dev/tty";
  }
  printLog("INFO", "Flushing " DEFAULT_INPUT_CHAIN);
  print(IPTABLES_CMD, "-F", DEFAULT_INPUT_CHAIN);
  printLog("INFO", "Flushing " DEFAULT_OUTPUT_CHAIN);
  print(IPTABLES_CMD, "-F", DEFAULT_OUTPUT_CHAIN);
  printLog("INFO", "Accepting loopback traffic on " DEFAULT_INPUT_CHAIN);
  print(IPTABLES_CMD, "-A", DEFAULT_INPUT_CHAIN,  "-i lo -j ACCEPT");
  printLog("INFO", "Accepting loopback traffic on " DEFAULT_OUTPUT_CHAIN);
  print(IPTABLES_CMD, "-A", DEFAULT_OUTPUT_CHAIN, "-o lo -j ACCEPT");
  printLog("INFO", "Enabling connection tracking on " DEFAULT_INPUT_CHAIN);
  print(IPTABLES_CMD, "-A", DEFAULT_INPUT_CHAIN,  "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT");
  printLog("INFO", "Enabling connection tracking on " DEFAULT_OUTPUT_CHAIN);
  print(IPTABLES_CMD, "-A", DEFAULT_OUTPUT_CHAIN, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT");
  printLog("INFO", "Accepting ICMP traffic from " DEFAULT_INPUT_CHAIN);
  print(IPTABLES_CMD, "-A", DEFAULT_INPUT_CHAIN, "-p icmp -j ACCEPT");
  split(DNS_SERVERS, _DNS_SERVERS);
  for(server in _DNS_SERVERS) {
    printLog("INFO", "New outbound rule - " sprintf("%15s", _DNS_SERVERS[server]) ":" colored("yellow", sprintf("%5d", 53)) "/udp (" colored("blue", "DNS") ")");
    print(IPTABLES_CMD, "-A", DEFAULT_OUTPUT_CHAIN, "-p udp -m udp --dport 53 -d", _DNS_SERVERS[server], "-j ACCEPT");
  }
  split(UNRESTRICTED_SUBNETS, _UNRESTRICTED_SUBNETS);
  for(subnet in _UNRESTRICTED_SUBNETS) {
    printLog("INFO", "New inbound rule - " sprintf("%18s", _UNRESTRICTED_SUBNETS[subnet]) " (" colored("blue", "unrestricted subnet") ")");
    print(IPTABLES_CMD, "-A", DEFAULT_INPUT_CHAIN, "-d", _UNRESTRICTED_SUBNETS[subnet], "-j ACCEPT");
  }
  delete INPUT_RULES[0];
  delete OUTPUT_RULES[0];
}

function extractIP(string) {
  if(match(string, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
    return substr(string,RSTART,RLENGTH);
  }
  return "";
}

{
  if(match($7, "\"[^\"]+\""))
    name = substr($7,RSTART + 1,RLENGTH - 2);
  else
    name = "";
  split($6, remote, ":");
  remoteIP   = extractIP(remote[1]);
  if(remoteIP == "")
    printLog("WARNING", "Invalid remote IP for " colored("yellow", $6) " (" colored("blue", name) ")");
  if(remote[2] != "*" && (remote[2] < 1 || remote[2] > 65535))
    printLog("WARNING", "Invalid remote port for " colored("yellow", $6) " (" colored("blue", name) ")");
  split($5, local, ":");
  localIP   = extractIP(local[1]);
  if(localIP == "")
    printLog("WARNING", "Invalid local IP for "   colored("yellow", $5) " (" colored("blue", name) ")");
  if(local[2] != "*" && (local[2] < 1 || local[2] > 65535))
    printLog("WARNING", "Invalid local port for " colored("yellow", $5) " (" colored("blue", name) ")");
}

$2 in INBOUND_CONNECTION_TYPES_ARRAY {
  if(INPUT_RULES[local[2] "/" $1]) next;
  if(local[2] in INBOUND_PORT_WHITELIST_ARRAY == 0) {
    printLog("WARNING", "Inbound connection " formatPort(local[2], $1, name) " not in whitelist, skipping.");
    next;
  }
  if(name) comment = "-m comment --comment \"" name "\"";
  else     comment = "";
  print(IPTABLES_CMD " -A " DEFAULT_INPUT_CHAIN " -p " $1 " -m " $1 " --dport " local[2] " " comment " -j ACCEPT");
  printLog("INFO", "New inbound rule - " formatPort(local[2], $1, name));
  INPUT_RULES[local[2] "/" $1] = 1;
}

$2 in OUTBOUND_CONNECTION_TYPES_ARRAY {
  if(remoteIP) {
    if(OUTPUT_RULES[$6 "/" $1]) next;
  } else {
    if(OUTPUT_RULES[remote[2] "/" $1]) next;
  }
  if(remote[2] in OUTBOUND_PORT_WHITELIST_ARRAY == 0) {
    printLog("WARNING", "Outbound connection " formatPort(remote[2], $1, name) " not in whitelist, skipping.");
    next;
  }
  if(remoteIP) remoteIPMatcher = "-d " remoteIP;
  else         remoteIPMatcher = "";
  if(name) comment = "-m comment --comment \"" name "\"";
  else     comment = "";
  print(IPTABLES_CMD " -A " DEFAULT_OUTPUT_CHAIN " -p " $1 "-m " $1 " --dport " remote[2] " " remoteIPMatcher " -j ACCEPT");
  printLog("INFO", "New outbound rule - " sprintf("%15s", remoteIP) ":" formatPort(remote[2], $1, name));
  if(remoteIP) OUTPUT_RULES[$6 "/" $1] = 1;
  else         OUTPUT_RULES[remote[2] "/" $1] = 1;
}
EOF
    chmod +x "$tmpfile"
    sudo "$tmpfile"
    rm "$tmpfile"
    
    # Prompt the user for additional manual rules based on port numbers.
    manual_choice=$(get_input_string "Would you like to add additional iptables rules (port numbers)? (y/n): ")
    if [[ "$manual_choice" == "y" || "$manual_choice" == "Y" ]]; then
        custom_iptables_manual_rules
    fi
}

# FUNCTION: custom_iptables_manual_rules
# Prompts the user to input ports and then adds an iptables rule for each port.
function custom_iptables_manual_rules {
    print_banner "Manual IPtables Rule Addition"
    echo "[*] Enter port numbers (one per line) for which you wish to allow inbound TCP traffic."
    echo "    Press ENTER on a blank line when finished."
    ports=$(get_input_list)
    for port in $ports; do
        sudo iptables -A INPUT --protocol tcp --dport "$port" -j ACCEPT
        echo "[*] iptables rule added for port $port (TCP)"
    done
}

########################################################################

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

########################################################################
# MENU FUNCTION
# This function displays a menu of major parts of the script. The user may choose to run:
#   1) The full hardening script
#   2) User management (create users, change passwords, disable users, remove sudoers)
#   3) Firewall configuration (choose UFW or custom iptables)
#   4) Backups
#   5) Splunk installation
#   6) SSH hardening
#   7) PAM/profile fixes and system configuration (fix PAM, remove profiles, check permissions, sysctl config)
#   8) Web hardening
#   9) Exit
function show_menu {
    print_banner "Hardening Script Menu"
    echo "1) Full Hardening Script"
    echo "2) User Management"
    echo "3) Firewall Configuration"
    echo "4) Backups"
    echo "5) Splunk Installation"
    echo "6) SSH Hardening"
    echo "7) PAM/Profile Fixes & System Config"
    echo "8) Web Hardening"
    echo "9) Exit"
    echo
    read -p "Enter your choice [1-9]: " menu_choice
    echo
    case $menu_choice in
        1)
            main ;;
        2)
            detect_system_info
            install_prereqs
            create_ccdc_users
            change_passwords
            disable_users
            remove_sudoers ;;
        3)
            detect_system_info
            install_prereqs
            disable_other_firewalls
            echo "[*] Choose a firewall configuration method:"
            echo "    1) UFW"
            echo "    2) iptables (Custom)"
            read -p "Enter your choice [1-2]: " fw_choice
            case $fw_choice in
                1) setup_ufw ;;
                2) setup_custom_iptables ;;
                *) echo "[X] Invalid choice. Defaulting to UFW."; setup_ufw ;;
            esac ;;
        4)
            backups ;;
        5)
            setup_splunk ;;
        6)
            secure_ssh ;;
        7)
            fix_pam
            remove_profiles
            check_permissions
            sysctl_config ;;
        8)
            harden_web ;;
        9)
            echo "Exiting..."; exit 0 ;;
        *)
            echo "Invalid option. Exiting."
            exit 1 ;;
    esac
}

########################################################################
# MAIN FUNCTION: Runs the full hardening process
function main {
    echo "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    echo "[*] Start of full hardening process"
    detect_system_info
    install_prereqs
    create_ccdc_users
    change_passwords
    disable_users
    remove_sudoers
    disable_other_firewalls
    # --- FIREWALL CONFIGURATION SECTION ---
    echo "[*] Choose a firewall configuration method:"
    echo "    1) UFW"
    echo "    2) iptables (Custom)"
    read -p "Enter your choice [1-2]: " fw_choice
    case $fw_choice in
        1) setup_ufw ;;
        2) setup_custom_iptables ;;
        *) echo "[X] Invalid choice. Defaulting to UFW."; setup_ufw ;;
    esac
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
    echo "[*] End of full hardening process"
    echo "[*] Script log can be viewed at $LOG"
    echo "[*] ***Please install system updates now***"
    # After full hardening, optionally ask about web hardening.
    web_choice=$(get_input_string "Would you like to perform web hardening? (y/N): ")
    if [ "$web_choice" == "y" ]; then
        harden_web
    fi
}

########################################################################
# PARSE ARGUMENTS (e.g., --debug)
for arg in "$@"; do
    case "$arg" in
        --debug )
            echo "[*] Debug mode enabled"
            debug="true"
            ;;
    esac
done

########################################################################
# SET UP LOGGING DIRECTORY
LOG_PATH=$(dirname "$LOG")
if [ ! -d "$LOG_PATH" ]; then
    sudo mkdir -p "$LOG_PATH"
    sudo chown root:root "$LOG_PATH"
    sudo chmod 750 "$LOG_PATH"
fi

########################################################################
# MAIN EXECUTION: Instead of automatically running the full script, show the menu.
show_menu
