# Wrapper around python ldap3 library


## Description
- Python class with simplified CRUD operations for LDAP users and LDAP groups


## Advantages over ldap3
- Based on sAMAccountName rather than distinguishedName
- New useful methods like *auth_user()*, *modify_user()* or *delete_user_from_group()*
- Easy switching between prod and dev LDAP servers
- Easy switching between active and disabled users
- More verbose and easy to read errors than in ldap3


## Set up
    $ git clone https://github.com/popoviliya/ldap3_wrapper.git
    $ cd ldap3_wrapper
    $ sudo pip3 install --no-cache-dir -r requirements.txt

Credentials can either be provided 
- As environment variables
- In *.env* file 
- Passed into *LDAP3Wrapper()* instance as arguments

Use case examples can be found in [*use_cases.py*](use_cases.py) file


## Environment variables
### Mandatory
- LDAP_HOST - LDAP host address
- LDAP_BASE_DN - root LDAP dn
- LDAP_BIND_USER - sAMAccountName of bind user
- LDAP_BIND_PASSWORD - password of bind user
### Optional
- LDAP_PORT - LDAP host port (defaults to 389)
- LDAP_USERS_OU - LDAP OU with all active users (defaults to *OU=Users,{LDAP_BASE_DN}*)
- LDAP_DISABLED_USERS_OU - LDAP OU with all disabled users (defaults to *OU=DisabledUsers,{LDAP_BASE_DN}*)
- LDAP_GROUPS_OU - LDAP OU with all active groups (defaults to *OU=Groups,{LDAP_BASE_DN}*)
### For testing environment
- TEST_LDAP_HOST
- TEST_LDAP_BASE_DN
- TEST_LDAP_BIND_USER
- TEST_LDAP_BIND_PASSWORD
- TEST_LDAP_PORT
- TEST_LDAP_USERS_OU
- TEST_LDAP_DISABLED_USERS_OU
- TEST_LDAP_GROUPS_OU