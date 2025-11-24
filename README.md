# Manage_User_Server

## 🧑‍💻 User Management Shell Script

A modular and configuration-driven **Linux user management system** written in Bash.

This tool provides an interactive TUI-style interface for administrators to manage users, groups, permissions, and SFTP jails using configuration files.

It is designed for:

* multi-user servers
* shared environments
* educational platforms
* internal infrastructure
* hosting environments

---

## ✨ Features

✅ User creation with:

* automatic password generation
* forced password change on first login
* configurable group assignment

✅ User lifecycle management:

* add / update / delete users
* lock / unlock accounts
* reset passwords

✅ Groups & permissions automation:

* automatic group creation
* directory creation with correct permissions (setgid)
* bind-mounted shared folders

✅ SFTP / SSH isolation:

* optional chroot jail per user
* symlinked group directories
* automatic `sshd_config` configuration
* internal-sftp restriction

✅ Configuration-based behavior:

* `groups.conf`
* `users.conf`
* `admins.conf`

✅ Safety features:

* backup home directory on deletion
* log with rotation
* configuration validation
* authorization check

---

## 🧩 Configuration Files

The script relies on three configuration files:

### `groups.conf`

Defines groups and their shared directories:

```
dev:/srv/dev,/srv/tools
clients:/srv/clients
interns
```

Format:

```
group_name[:folder1,folder2,...]
```

---

### `admins.conf`

Lists users authorized to run the script:

```
root
gestion
```

If missing, it is automatically created.

---

### `users.conf`

Maintained automatically, maps users to groups:

```
alice:dev
bob:clients
```

---

## 🛠 Requirements

The following tools must be available:

* `openssl`
* `getent`
* `useradd`
* `usermod`
* `userdel`
* `gpasswd`
* `chpasswd`
* `tar`
* `groupadd`
* `systemctl`
* `mount`

🔐 Run with sufficient privileges (typically via `sudo`).

---

## 🚀 Installation

```bash
git clone <repo>
cd <repo>
chmod +x manage_users.sh
# (Optional) Install configuration files
cp configs/*.conf .
```

---

## ▶️ Usage

Run:

```bash
sudo ./manage_users.sh
```

Menu options:

```
1) Add user
2) Update user role
3) Delete user
4) List users per group
5) Reset user password
6) Manage configuration files
7) Lock user
8) Unlock user
0) Quit
```

---

## 🔐 SFTP Jail Behavior

When a user is created or updated:

* `/home/jail/<user>` is created
* a private `data/` folder is assigned
* group folders are bind-mounted inside the jail
* SSH access can be restricted to SFTP only via:

```
Match User <username>
    ChrootDirectory /home/jail/<username>
    ForceCommand internal-sftp
```

---

## 📦 Backup

Before deleting a user, the script archives their home directory:

```
/srv/archives/<user>_YYYY-MM-DD.tar.gz
```

---

## 📝 Logging

Log file:

```
log/manage_users.log
```

Log rotation:

* keeps ~5,000 lines
* trims to ~4,000

---

## ✅ Security

This script implements:

* admin whitelist
* permission enforcement on shared directories
* jailed environments
* forced password renewal
* log auditing

---

## 🧪 Configuration Validation

At startup the script validates:

* group names
* directory accessibility
* admin existence
* configuration format

Execution stops if critical errors are found.

---

## 🗂 Example Workflow

Add a user:

1. Run the script
2. Select `1) Add user`
3. Enter username
4. Select groups
5. Provide the temporary password
6. User logs in and must change their password

---

## 🏗 Project Structure

```
manage_users.sh
groups.conf
users.conf
admins.conf
log/
```

---

## ⭐ Author

Developed for internal server administration automation in CSS (ULiège).
Created to simplify and secure multi-user Linux environments.
