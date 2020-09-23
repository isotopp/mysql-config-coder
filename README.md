# mysql-config-coder
Encode and decode .mylogin.cnf files

.mylogin.cnf files are not encrypted, just obfuscated: They contain the key necessary to decrypt them.

The mysql_config_editor program does not let you specify a password on the command line, only interactively. This can make provisioning hard.
Using mysql_config_coder, you can write out plaintext .mylogin.cnf files (eg using Ansible templates) and then encrypt them. As this is done
without terminal interaction, it can easily be scripted.
