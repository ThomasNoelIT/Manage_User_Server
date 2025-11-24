#!/bin/bash

# ===============================
# User Management Script
# Handles user creation, deletion, updates, SFTP jail, group assignments
# ===============================

set -euo pipefail
IFS=$'\n\t'

# --- Config ----------------------------------------------------------------
GROUP_CONFIG="groups.conf"
LOGFILE="log/manage_users.log"
USERS_CONFIG="users.conf"  
ADMINS_CONFIG="admins.conf"

# Ensure required commands exist
for cmd in openssl getent gpasswd useradd usermod userdel chpasswd chage tar groupadd; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Missing command: $cmd"; exit 1; }
done

# --- Helpers ---------------------------------------------------------------

# Trim leading and trailing whitespace from a string
trim() {
    local var="$*"
    var="${var#"${var%%[![:space:]]*}"}"
    var="${var%"${var##*[![:space:]]}"}"
    printf '%s' "$var"
}

# Generate a random password (base64, 14 chars)
generate_password() { openssl rand -base64 14; }

# Log an action with timestamp and current user
log_action() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$(whoami)] - $1" >> "$LOGFILE"
}

# --- Manage users.conf ------------------------------------------------------

# Synchronize users.conf based on current group memberships
sync_users_conf() {
    : > "$USERS_CONFIG"  # Clear existing content
    for g in "${GROUPS[@]}"; do
        members=$(getent group "$g" | cut -d: -f4 | tr ',' ' ')
        for u in $members; do
            echo "$u:$g" >> "$USERS_CONFIG"
        done
    done
    chmod 640 "$USERS_CONFIG"
}

# Update or add a user's entry in users.conf
update_users_conf_entry() {
    local username=$1
    local groups=$2
    # Remove existing entries for user
    sed -i "/^$username:/d" "$USERS_CONFIG"
    for g in $groups; do
        echo "$username:$g" >> "$USERS_CONFIG"
    done
}

# Remove a user's entry from users.conf
remove_users_conf_entry() {
    local username=$1
    sed -i "/^$username:/d" "$USERS_CONFIG"
}

# --- Load groups config ---------------------------------------------------

# Load groups and their associated directories from groups.conf
load_groups() {
    while IFS= read -r line || [ -n "$line" ]; do
        line=$(trim "$line")
        [ -z "$line" ] && continue
        case "$line" in \#*) continue ;; esac  # skip comments

        if [[ "$line" == *:* ]]; then
            group="${line%%:*}"
            dirs="${line#*:}"
        else
            group="$line"
            dirs=""
        fi

        group=$(trim "$group")
        dirs=$(trim "$dirs")

        abs_dirs=""
        if [ -n "$dirs" ]; then
            # Convert relative paths to absolute
            IFS=',' read -ra dir_array <<< "$dirs"
            for d in "${dir_array[@]}"; do
                d=$(trim "$d")
                d=$(eval echo "$d")       # expand ~
                d=$(realpath -m "$d")     # canonical absolute path
                abs_dirs+="$d,"
            done
            abs_dirs="${abs_dirs%,}"
        fi

        GROUPS+=("$group")
        GROUP_DIRS+=("$abs_dirs")
    done < "$GROUP_CONFIG"
}

# --- Load admins config ---------------------------------------------------

# Load the list of admin users from admins.conf
load_admins() {
    ADMINS=()
    if [ ! -f "$ADMINS_CONFIG" ]; then
        mkdir -p "$(dirname "$ADMINS_CONFIG")"
        echo -e "root\ngestion" > "$ADMINS_CONFIG"
        chmod 644 "$ADMINS_CONFIG"
        echo "Created default admins config at $ADMINS_CONFIG"
    fi

    while IFS= read -r line || [ -n "$line" ]; do
        line=$(trim "$line")
        [ -z "$line" ] && continue
        case "$line" in \#*) continue ;; esac  # skip comments
        ADMINS+=("$line")
    done < "$ADMINS_CONFIG"
}

# --- Ensure groups and directories exist & correct permissions --------------

ensure_groups_and_dirs() {
    for i in "${!GROUPS[@]}"; do
        g="${GROUPS[$i]}"
        dlist="${GROUP_DIRS[$i]:-}"

        # Create group if it does not exist
        if ! getent group "$g" >/dev/null; then
            groupadd "$g"
            echo "Created group: $g"
            log_action "Created group $g"
        fi

        if [ -n "$dlist" ]; then
            IFS=',' read -ra dirs_arr <<< "$dlist"
            for rawdir in "${dirs_arr[@]}"; do
                dir=$(trim "$rawdir")
                [ -z "$dir" ] && continue

                # Create directory with setgid so files inherit group
                sudo mkdir -p "$dir"
                sudo chgrp -R "$g" "$dir"
                sudo chmod -R 2775 "$dir"             # drwxrwsr-x
                sudo find "$dir" -type f -exec chmod 664 {} \;   # rw-rw-r-- files
                sudo find "$dir" -type d -exec chmod 2775 {} \;  # rwxrwsr-x directories

                log_action "Ensured dir $dir exists, group $g, perms 770"

                # Add admins to each group
                for admin in "${ADMINS[@]}"; do
                    if id "$admin" &>/dev/null; then
                        usermod -aG "$g" "$admin"
                    fi
                done
            done
        fi
    done
}

# --- Display groups for selection -----------------------------------------

# Show groups with numbers for selection in user assignment
list_groups_for_selection() {
    echo "Available groups (num -> group : directories):"
    for i in "${!GROUPS[@]}"; do
        idx=$((i+1))
        echo "  $idx) ${GROUPS[$i]} : ${GROUP_DIRS[$i]:-<no dir>}"
    done
    echo ""
    echo "Choose one or more numbers separated by commas (ex: 1,3)."
    echo "Leave empty or 0 for no group."
}

# --- Assign groups to user ------------------------------------------------

# Assign selected groups to a user and update users.conf
assign_group() {
    local username=$1
    local selection=$2

    # Remove user from all existing groups first
    for g in "${GROUPS[@]}"; do
        gpasswd -d "$username" "$g" >/dev/null 2>&1 || true
    done

    if [ -z "$(trim "$selection")" ] || [ "$(trim "$selection")" = "0" ]; then
        update_users_conf_entry "$username" ""
        return 0
    fi

    IFS=',' read -ra sel_arr <<< "$selection"
    local groups_assigned=()
    for token in "${sel_arr[@]}"; do
        token=$(trim "$token")
        [ -z "$token" ] && continue
        if ! [[ "$token" =~ ^[0-9]+$ ]]; then
            echo "Invalid selection: $token" >&2
            return 0
        fi
        local idx=$((token - 1))
        if (( idx < 0 || idx >= ${#GROUPS[@]} )); then
            echo "Selection out of range: $token" >&2
            return 0
        fi
        local target_group="${GROUPS[idx]}"
        usermod -aG "$target_group" "$username"
        groups_assigned+=("$target_group")
    done

    # Update users.conf with the new group list
    update_users_conf_entry "$username" "${groups_assigned[*]}"

    # Return assigned groups as a space-separated string
    printf '%s' "${groups_assigned[*]}"
}

# --- Display users and their roles ----------------------------------------

display_users_with_roles() {
    echo "----------------------------"
    echo "Current users and their roles (from users.conf):"

    # Display users with groups from users.conf
    if [ -f "$USERS_CONFIG" ] && [ -s "$USERS_CONFIG" ]; then
        while IFS=: read -r user groups; do
            echo " - $user : ${groups:-<no group>}"
        done < "$USERS_CONFIG"
    else
        echo "<no users defined in users.conf>"
    fi

    # Display users with no group assigned in users.conf
    echo ""
    echo "Users with no group assigned:"
    mapfile -t system_users < <(awk -F: '$3 >= 1000 {print $1}' /etc/passwd)

    # Build a set of users from users.conf
    declare -A users_in_conf
    if [ -f "$USERS_CONFIG" ] && [ -s "$USERS_CONFIG" ]; then
        while IFS=: read -r user _; do
            users_in_conf["$user"]=1
        done < "$USERS_CONFIG"
    fi

    for user in "${system_users[@]}"; do
        if [ -z "${users_in_conf[$user]:-}" ]; then
            echo " - $user : <no group>"
        fi
    done

    echo "----------------------------"
}




# --- Jail user in their home with symlinks to group dirs ------------------

# Create a chroot jail for a user and mount their group directories
jail_user() {
    local username=$1
    local groups=$2

    local jail_home="/home/jail/$username"
    sudo mkdir -p "$jail_home"
    sudo chown root:root "$jail_home"
    sudo chmod 755 "$jail_home"

    # Create user-specific private data folder
    local data_dir="$jail_home/data"
    sudo mkdir -p "$data_dir"
    sudo chown "$username:$username" "$data_dir"
    sudo chmod 750 "$data_dir"

    # Unmount old directories in the jail except data
    for mnt in "$jail_home"/*; do
        [ -d "$mnt" ] || continue
        sudo umount -f "$mnt" 2>/dev/null || true
        base=$(basename "$mnt")
        if [ "$base" != "data" ]; then
            sudo rm -rf "$mnt" 2>/dev/null || true
        fi
    done

    # Mount group directories as bind mounts inside the jail
    for g in $groups; do
        local group_dir
        group_dir=$(grep "^$g:" "$GROUP_CONFIG" | cut -d: -f2)
        [ -z "$group_dir" ] && { echo "⚠️ No folder defined for group $g"; continue; }

        group_dir=$(realpath -m "$group_dir")
        [ ! -d "$group_dir" ] && sudo mkdir -p "$group_dir"

        # Ensure group ownership and permissions
        sudo chgrp -R "$g" "$group_dir"
        sudo chmod -R g+rw "$group_dir"
        sudo find "$group_dir" -type d -exec chmod g+s {} +

        # Mount into the jail
        local mount_point="$jail_home/$g"
        sudo mkdir -p "$mount_point"
        sudo mount --bind "$group_dir" "$mount_point"

        # Persist in fstab if not already present
        if ! grep -q "$mount_point" /etc/fstab; then
            echo "$group_dir  $mount_point  none  bind  0  0" | sudo tee -a /etc/fstab >/dev/null
        fi

        echo "Folder $group_dir mounted in jail for $username ($mount_point)"
    done

    # Update user's home directory and shell
    sudo usermod -d "$jail_home" -s /bin/bash "$username"
}

# --- Update sshd_config for SFTP jail --------------------------------------

# Add Match block to sshd_config for chrooted SFTP access
# type="sftp" or "shell"
update_sshd_config_for_user() {
    local username=$1
    local jail_home="/home/jail/$username"
    local type=${2:-shell}  # default shell

    # Remove previous Match block for the user
    sudo sed -i "/^Match User $username$/,/^$/d" /etc/ssh/sshd_config

    if [ "$type" = "sftp" ]; then
        echo -e "Match User $username\n    ChrootDirectory $jail_home\n    ForceCommand internal-sftp\n    AllowTcpForwarding no\n    X11Forwarding no\n" | sudo tee -a /etc/ssh/sshd_config >/dev/null
    else
        echo "User $username allowed normal shell (no SFTP jail)"
    fi

    sudo systemctl reload ssh
    echo "sshd_config updated and reloaded for user $username"
}


# --- CRUD user functions --------------------------------------------------

# Add a new user, assign groups, create jail, force password change
add_user() {
    read -p "Enter new username: " username
    username=$(trim "$username")

    if ! [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        echo "Invalid username format."
        return 0 
    fi

    if id "$username" &>/dev/null; then
        echo "User '$username' already exists."
        return 0
    fi

    list_groups_for_selection
    read -p "Group numbers: " selection

    password=$(generate_password)

    useradd -m -s /bin/bash "$username"
    echo "$username:$password" | chpasswd
    chage -d 0 "$username"   # force password change on first login

    assigned=$(assign_group "$username" "$selection")
    jail_user "$username" "$assigned"
    echo "User '$username' created successfully."
    echo "Temporary password: $password"
    log_action "User '$username' created; groups: ${assigned:-<none>}"
    
    update_sshd_config_for_user "$username"
}

# Update existing user's group assignments and jail
update_user() {
    display_users_with_roles

    read -p "Enter username to update: " username
    username=$(trim "$username")

    if ! [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        echo "Invalid username format."
        return 0 
    fi

    if ! id "$username" &>/dev/null; then
        echo "User '$username' does not exist."
        return 0
    fi

    list_groups_for_selection
    read -p "New group numbers: " selection

    assigned=$(assign_group "$username" "$selection")
    jail_user "$username" "$assigned"
    echo "Updated roles for user '$username'."
    log_action "User '$username' role updated to groups: ${assigned:-<none>}"
    
    update_sshd_config_for_user "$username"
}


# Delete a user with backup of home directory
delete_user() {
    display_users_with_roles   # <-- Affiche les users et leurs rôles

    read -p "Enter username to delete: " username
    username=$(trim "$username")

    if ! id "$username" &>/dev/null; then
        echo "User '$username' does not exist."
        return 0
    fi

    read -p "Are you sure you want to delete '$username'? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        mkdir -p /srv/archives
        if [ -d "/home/$username" ]; then
            tar -czf "/srv/archives/${username}_$(date +%F).tar.gz" "/home/$username" || true
        fi
        userdel -r "$username"
        remove_users_conf_entry "$username"
        echo "User '$username' deleted (backup stored in /srv/archives)."
        log_action "User '$username' deleted"
    else
        echo "Operation cancelled."
    fi
}


# --- List users per defined group ----------------------------------------

# Print all groups and members, and the users.conf content
list_users() {
    echo "Configured groups and members:"
    for i in "${!GROUPS[@]}"; do
        g="${GROUPS[$i]}"
        dirs="${GROUP_DIRS[$i]:-<no dir>}"
        members=$(getent group "$g" | cut -d: -f4)
        echo " - $g : $dirs"
        echo "     members: ${members:-<none>}"
    done
    echo ""
    echo "From $USERS_CONFIG:"
    cat "$USERS_CONFIG" 2>/dev/null || echo "<empty>"

    display_users_with_roles
}

# --- Reset user password --------------------------------------------------

# Regenerate password for a user and force them to change at next login
reset_password() {
    read -p "Enter username to reset password: " username
    username=$(trim "$username")

    if ! id "$username" &>/dev/null; then
        echo "User '$username' does not exist."
        return 0
    fi

    new_password=$(generate_password)
    echo "$username:$new_password" | sudo chpasswd
    sudo passwd -e "$username"   # expire immédiatement le mot de passe

    echo "Password for '$username' has been reset."
    echo "Temporary password: $new_password"
    echo "⚠️ The user will be asked to change it at next login."
    echo "   If SSH closes immediately, reconnect with:"
    echo "   ssh -t $username@<server> passwd"
    log_action "Password for '$username' reset and expired (must be changed at next login)."
}


# --- Log cleanup ----------------------------------------------------------
# Keep only the last N log files, delete older ones to save disk space
cleanup_log() {
    local logfile="$LOGFILE"
    local max_lines=5000     # Maximum lines to keep
    local reduce_by=500      # Number of oldest lines to remove at once
    local min_lines=4000     # Target after cleanup

    # If logfile doesn't exist, do nothing
    [ ! -f "$logfile" ] && return 0

    local current_lines
    current_lines=$(wc -l < "$logfile")

    if (( current_lines > max_lines )); then
        # Calculate how many lines to keep after removing oldest block(s)
        local target_lines=$((current_lines - reduce_by))
        if (( target_lines < min_lines )); then
            target_lines=$min_lines
        fi

        # Keep only the last $target_lines lines
        tail -n "$target_lines" "$logfile" > "${logfile}.tmp" && mv "${logfile}.tmp" "$logfile"
        echo "Log cleaned: reduced from $current_lines to $target_lines lines."
    fi
}

# --- Validate configuration -------------------------------------------------

validate_config() {
    local errors=0

    # Vérifier que les groupes sont valides
    for g in "${GROUPS[@]}"; do
        if ! [[ "$g" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
            echo "❌ Nom de groupe invalide dans groups.conf: '$g'" >&2
            ((errors++))
        fi
    done

    # Vérifier que les répertoires existent (ou sont créables)
    for dirs in "${GROUP_DIRS[@]}"; do
        IFS=',' read -ra dlist <<< "$dirs"
        for d in "${dlist[@]}"; do
            [ -z "$d" ] && continue
            if ! mkdir -p "$d" 2>/dev/null; then
                echo "❌ Impossible de créer ou accéder au dossier: $d" >&2
                ((errors++))
            fi
        done
    done

    # Vérifier que les admins existent sur le système
    for admin in "${ADMINS[@]}"; do
        if ! id "$admin" &>/dev/null; then
            echo "⚠️ Admin '$admin' défini dans admins.conf n'existe pas encore."
        fi
    done

    if ((errors > 0)); then
        echo "⚠️ Erreurs de configuration détectées ($errors). Corrige avant de continuer."
        exit 1
    else
        echo "✅ Configuration validée avec succès."
    fi
}


# --- Config management functions ------------------------------------------

# Generic function to edit a config file
edit_config_file() {
    local file="$1"
    local action
    while true; do
        echo ""
        echo "Editing $file"
        echo "1) Add entry"
        echo "2) Update entry"
        echo "3) Delete entry"
        echo "0) Back"
        read -p "Choice: " action
        action=$(trim "$action")

        case "$action" in
            1) add_entry "$file" ;;
            2) update_entry "$file" ;;
            3) delete_entry "$file" ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

# Add entry to a file
add_entry() {
    local file="$1"
    read -p "Enter new entry: " entry
    entry=$(trim "$entry")
    if [ -n "$entry" ]; then
        echo "$entry" >> "$file"
        echo "Entry added."
        log_action "Added entry to $file: $entry"
    else
        echo "Empty entry, nothing added."
    fi
}

# Update entry in a file
update_entry() {
    local file="$1"
    read -p "Enter the entry to update (exact match): " old_entry
    old_entry=$(trim "$old_entry")
    if ! grep -qxF "$old_entry" "$file"; then
        echo "Entry not found."
        return
    fi
    read -p "Enter the new entry: " new_entry
    new_entry=$(trim "$new_entry")
    if [ -n "$new_entry" ]; then
        sed -i "s|^${old_entry}$|${new_entry}|" "$file"
        echo "Entry updated."
        log_action "Updated entry in $file: '$old_entry' -> '$new_entry'"
    else
        echo "Empty entry, update cancelled."
    fi
}

# Delete entry from a file
delete_entry() {
    local file="$1"
    read -p "Enter the entry to delete (exact match): " entry
    entry=$(trim "$entry")
    if grep -qxF "$entry" "$file"; then
        sed -i "/^${entry}$/d" "$file"
        echo "Entry deleted."
        log_action "Deleted entry from $file: $entry"
    else
        echo "Entry not found."
    fi
}

# --- Sub-menu for configuration files -------------------------------------
manage_configs() {
    while true; do
        echo ""
        echo "Manage configuration files"
        echo "1) groups.conf"
        echo "2) admins.conf"
        echo "3) users.conf"
        echo "0) Back"
        read -p "Choice: " choice
        choice=$(trim "$choice")
        case "$choice" in
            1) edit_config_file "$GROUP_CONFIG" ;;
            2) edit_config_file "$ADMINS_CONFIG" ;;
            3) edit_config_file "$USERS_CONFIG" ;;
            0) break ;;
            *) echo "Invalid choice." ;;
        esac
    done
}


# --- Lock or unlock user accounts ------------------------------------------

lock_user() {
    read -p "Enter username to lock: " username
    username=$(trim "$username")

    if ! id "$username" &>/dev/null; then
        echo "User '$username' does not exist."
        return 0
    fi

    usermod -L "$username"
    passwd -l "$username" >/dev/null 2>&1 || true
    echo "🔒 User '$username' has been locked."
    log_action "User '$username' locked"
}

unlock_user() {
    read -p "Enter username to unlock: " username
    username=$(trim "$username")

    if ! id "$username" &>/dev/null; then
        echo "User '$username' does not exist."
        return 0
    fi

    usermod -U "$username"
    passwd -u "$username" >/dev/null 2>&1 || true
    echo "🔓 User '$username' has been unlocked."
    log_action "User '$username' unlocked"
}



# --- Start ----------------------------------------------------------------

unset GROUPS GROUP_DIRS
declare -a GROUPS
declare -a GROUP_DIRS

load_admins
load_groups
validate_config

if [ "${#GROUPS[@]}" -gt 0 ]; then
    for i in "${!GROUPS[@]}"; do 
        group="${GROUPS[$i]}" 
        dir="${GROUP_DIRS[$i]:-<no dir>}"
        echo " - $group -> $dir"
    done 
else 
    echo "DEBUG: No groups loaded" 
fi

ensure_groups_and_dirs

# Check if current user is authorized to run script
current_user="$(id -un)"
authorized=false
for admin in "${ADMINS[@]}"; do
    if [[ "$current_user" == "$admin" ]]; then
        authorized=true
        break
    fi
done

if ! $authorized; then
    echo "User '$current_user' is not authorized to run this script."
    exit 1
fi

# Ensure log file exists and has correct perms
touch "$LOGFILE"
chown gestion:gestion "$LOGFILE" 2>/dev/null || true
chmod 600 "$LOGFILE" 2>/dev/null || true

# Ensure users.conf exists and sync it
touch "$USERS_CONFIG"   
chmod 640 "$USERS_CONFIG"
sync_users_conf
cleanup_log

# --- Main menu ------------------------------------------------------------
while true; do
    echo ""
    echo "Choose an action:"
    echo "1) Add user"
    echo "2) Update user role"
    echo "3) Delete user"
    echo "4) List users per group"
    echo "5) Reset user password"
    echo "6) Manage configuration files"
    echo "7) Lock user"
    echo "8) Unlock user"
    echo "0) Quit"
    read -p "Choice: " action

    case "$(trim "$action")" in
        1) add_user ;;
        2) update_user ;;
        3) delete_user ;;
        4) list_users ;;
        5) reset_password ;;
        6) manage_configs ;;
        7) lock_user ;;
        8) unlock_user ;;
        0) echo "Exiting."; break ;;
        *) echo "Invalid choice." ;;
    esac
done

