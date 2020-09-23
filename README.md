# mysql-config-coder
Encode and decode .mylogin.cnf files

.mylogin.cnf files are not encrypted, just obfuscated: They contain the key necessary to decrypt them.

The mysql_config_editor program does not let you specify a password on the command line, only interactively. This can make provisioning hard.
Using mysql_config_coder, you can write out plaintext .mylogin.cnf files (eg using Ansible templates) and then encrypt them. As this is done
without terminal interaction, it can easily be scripted.

## Installation

```
python -mvenv venv
source venv/bin/activate
pip install --upgrade pip
pip install wheel
pip install -r requirements.txt
```

## Usage

```
# generate a dummy file
mysql_config_editor set --login-path=local --user=root --host=localhost --passwd
Password: keks

# decode this file
./mysql_config_coder.py decode ~/.mylogin.cnf mylogin.out
cat mylogin.out

# make changes to mylogin.out and
./mysql_config_coder.py encode mylogin.out mylogin.cnf
chmod 600 mylogin.cnf

# test with original
MYSQL_TEST_LOGIN_FILE=$(pwd)/mylogin.cnf
mysql_config_editor -v print --all

# Note: mysql_config_editor will not print the password, just five stars
```
