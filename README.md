# mysql-config-coder
Encode and decode .mylogin.cnf files

.mylogin.cnf files are not encrypted, just obfuscated: They contain the key necessary to decrypt them.

The mysql_config_editor program does not let you specify a password on the command line, only interactively. This can make provisioning hard.
Using mysql_config_coder, you can write out plaintext .mylogin.cnf files (eg using Ansible templates) and then encrypt them. As this is done
without terminal interaction, it can easily be scripted.

## Installation

```sh
uv tool install .
```

## Usage

```
# generate a dummy file
mysql_config_editor set --login-path=local --user=root --host=localhost --password
Password: keks

# decode this file
mysql_config_coder decode ~/.mylogin.cnf mylogin.out
cat mylogin.out

# make changes to mylogin.out and
mysql_config_coder encode mylogin.out mylogin.cnf
chmod 600 mylogin.cnf

# test with original
export MYSQL_TEST_LOGIN_FILE=$(pwd)/mylogin.cnf
mysql_config_editor -v print --all
my_print_defaults -s local

# Note: mysql_config_editor will not print the password, just five stars
#       but my_print_defaults should also show the password.
```

For development, run the command and checks in the project environment:

```sh
uv run mysql_config_coder --help
uv run ruff check --fix
uv run ruff format
uv run pytest
uv run ty check
```

## Blog Article

[Provisioning .mylogin.cnf](https://blog.koehntopp.info/2020/09/23/mylogin-cnf.html)
