from dotenv import load_dotenv
import os
import ldap3
import json


class LDAP3Wrapper:
    """
    Python class with simplified CRUD operations for LDAP users and LDAP groups
    :param is_prod: A toggle between production and testing environments
    :param ldap_host: LDAP host address
    :param ldap_base_dn: root LDAP dn
    :param ldap_bind_user: sAMAccountName of bind user
    :param ldap_bind_password: password of bind user
    """
    def __init__(self,
                 *,
                 is_prod: bool = True,
                 ldap_host: str = None,
                 ldap_base_dn: str = None,
                 ldap_bind_user: str = None,
                 ldap_bind_password: str = None,
                 ldap_port: int = None,
                 ldap_users_ou: str = None,
                 ldap_disabled_users_ou: str = None,
                 ldap_groups_ou: str = None,
                 test_ldap_host: str = None,
                 test_ldap_base_dn: str = None,
                 test_ldap_bind_user: str = None,
                 test_ldap_bind_password: str = None,
                 test_ldap_port: int = None,
                 test_ldap_users_ou: str = None,
                 test_ldap_disabled_users_ou: str = None,
                 test_ldap_groups_ou: str = None) -> None:
        load_dotenv()

        self.is_prod = is_prod
        if self.is_prod:
            self.host = os.getenv("LDAP_HOST", ldap_host)
            self.base_dn = os.getenv("LDAP_BASE_DN", ldap_base_dn)
            self.bind_user = os.getenv("LDAP_BIND_USER", ldap_bind_user)
            self.bind_password = os.getenv("LDAP_BIND_PASSWORD", ldap_bind_password)
            self.port = int(os.getenv("LDAP_PORT", ldap_port or 389))
            self.users_ou = os.getenv("LDAP_USERS_OU", ldap_users_ou or f"OU=Users,{self.base_dn}")
            self.disabled_users_ou = os.getenv("LDAP_DISABLED_USERS_OU", ldap_disabled_users_ou or f"OU=DisabledUsers,{self.base_dn}")
            self.groups_ou = os.getenv("LDAP_GROUPS_OU", ldap_groups_ou or f"OU=Groups,{self.base_dn}")
        else:
            self.host = os.getenv("TEST_LDAP_HOST", test_ldap_host)
            self.base_dn = os.getenv("TEST_LDAP_BASE_DN", test_ldap_base_dn)
            self.bind_user = os.getenv("TEST_LDAP_BIND_USER", test_ldap_bind_user)
            self.bind_password = os.getenv("TEST_LDAP_BIND_PASSWORD", test_ldap_bind_password)
            self.port = int(os.getenv("TEST_LDAP_PORT", test_ldap_port or 389))
            self.users_ou = os.getenv("TEST_LDAP_USERS_OU", test_ldap_users_ou or f"OU=Users,{self.base_dn}")
            self.disabled_users_ou = os.getenv("TEST_LDAP_DISABLED_USERS_OU", test_ldap_disabled_users_ou or f"OU=DisabledUsers,{self.base_dn}")
            self.groups_ou = os.getenv("TEST_LDAP_GROUPS_OU", test_ldap_groups_ou or f"OU=Groups,{self.base_dn}")

        if any(_ is None for _ in [self.host, self.base_dn,
                                   self.bind_user, self.bind_password]):
            if self.is_prod:
                raise IndexError("Some PROD credentials are not provided (LDAP_HOST, LDAP_BASE_DN, LDAP_BIND_USER, LDAP_BIND_PASSWORD)")
            else:
                raise IndexError("Some TEST credentials are not provided (TEST_LDAP_HOST, TEST_LDAP_BASE_DN, TEST_LDAP_BIND_USER, TEST_LDAP_BIND_PASSWORD)")

    def connect_to_ldap(self) -> ldap3.Connection:
        """
        Connect to LDAP
        :return: ldap3.Connection
        :raises IndexError: If wrong LDAP_BIND_USER or wrong LDAP_BIND_PASSWORD or
                            if LDAP_BIND_PASSWORD not provided or
                            if wrong LDAP_HOST or can't connect to LDAP_HOST
        """
        try:
            ldap_server: ldap3.Server = ldap3.Server(host=self.host,
                                                     get_info=ldap3.ALL,
                                                     connect_timeout=2,
                                                     use_ssl=True)
            ldap_connection: ldap3.Connection = ldap3.Connection(server=ldap_server,
                                                                 user=self.bind_user,
                                                                 password=self.bind_password,
                                                                 receive_timeout=2,
                                                                 raise_exceptions=True)
            ldap_connection.bind()
            return ldap_connection
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            raise IndexError("Connection to LDAP failed (wrong LDAP_BIND_USER or LDAP_BIND_PASSWORD)")
        except ldap3.core.exceptions.LDAPPasswordIsMandatoryError:
            raise IndexError("Connection to LDAP failed (LDAP_BIND_PASSWORD not provided)")
        except ldap3.core.exceptions.LDAPSocketOpenError:
            raise IndexError("Connection to LDAP failed (wrong LDAP_HOST or can't connect to LDAP_HOST)")

    def add_user(self,
                 attributes: dict) -> dict:
        """
        Create a specific user
        :param attributes: A dictionary with new attributes and their values
        :return: A dictionary with result logs
        :raises IndexError: If attributes 'distinguishedName' and 'sAMAccountName' are not provided or
                            if 'distinguishedName' or 'sAMAccountName' aren`t unique or
                            if some attributes can only be added after a password change
        """
        if ("distinguishedName" not in attributes) or ("sAMAccountName" not in attributes):
            raise IndexError(f"Attributes 'distinguishedName' and 'sAMAccountName' are mandatory")
        ldap_connection: ldap3.Connection = self.connect_to_ldap()
        try:
            ldap_connection.add(dn=f"{attributes['distinguishedName']},{self.users_ou}",
                                attributes=attributes)
            return ldap_connection.result
        except ldap3.core.exceptions.LDAPEntryAlreadyExistsResult:
            raise IndexError(f"User '{attributes['distinguishedName']}' already exists in AD (distinguishedName or sAMAccountName aren`t unique)")
        except ldap3.core.exceptions.LDAPUnwillingToPerformResult:
            raise IndexError("Some attributes can only be added after a password change (e.g. userAccountControl)")

    def get_all_users(self,
                      attributes: list[str] = None,
                      search_disabled: bool = False,
                      search_filter: str = "(objectClass=user)") -> list[dict]:
        """
        Get the attributes of all users
        :param attributes: A list of attributes to get, use ["*"] for all attributes
        :param search_disabled: A toggle between active and disabled users
        :param search_filter: A filter for searching users
        :return: A list of dictionaries with selected attributes
        """
        attributes: list[str] = attributes or ["sAMAccountName"]
        search_base: str = self.disabled_users_ou if search_disabled else self.users_ou
        ldap_connection: ldap3.Connection = self.connect_to_ldap()
        ldap_connection.search(search_base=search_base,
                               search_filter=search_filter,
                               attributes=attributes)
        users_attributes: list[dict] = json.loads(ldap_connection.response_to_json())["entries"]
        return [user["attributes"] for user in users_attributes]

    def get_user(self,
                 sAMAccountName: str,
                 attributes: list[str] = None,
                 search_disabled: bool = False) -> dict:
        """
        Get the attributes of a specific user
        :param sAMAccountName: The login of the user
        :param attributes: A list of attributes to get, use ["*"] for all attributes
        :param search_disabled: A toggle between active and disabled users
        :return: A dictionary with selected attributes
        :raises IndexError: If the user does not exist
        """
        attributes: list[str] = attributes or ["sAMAccountName"]
        search_base: str = self.disabled_users_ou if search_disabled else self.users_ou
        ldap_connection: ldap3.Connection = self.connect_to_ldap()
        ldap_connection.search(search_base=search_base,
                               search_filter=f"(sAMAccountName={sAMAccountName})",
                               attributes=attributes)
        try:
            user_attributes: dict = json.loads(ldap_connection.response_to_json())["entries"][0]["attributes"]
            return user_attributes
        except IndexError:
            raise IndexError(f"User '{sAMAccountName}' doesn't exist")

    def user_exists(self,
                    sAMAccountName: str,
                    search_disabled: bool = False) -> bool:
        """
        Check if a specific user exists
        :param sAMAccountName: The login of the user
        :param search_disabled: A toggle between active and disabled users
        :return: True or False
        """
        try:
            self.get_user(sAMAccountName=sAMAccountName,
                          search_disabled=search_disabled)
            return True
        except Exception:
            return False

    def user_in_group(self,
                      user_sAMAccountName: str,
                      group_sAMAccountName: str) -> bool:
        """
        Check if a specific user is in a specific group
        :param user_sAMAccountName: The login of the user
        :param group_sAMAccountName: The sAMAccountName of the group
        :return: True or False
        """
        user_distinguishedName: str = self.get_user(sAMAccountName=user_sAMAccountName,
                                                    attributes=["distinguishedName"])["distinguishedName"]
        group_member: list[str] = self.get_group(sAMAccountName=group_sAMAccountName,
                                                 attributes=["member"])["member"]
        return user_distinguishedName in group_member

    def auth_user(self,
                  user: str,
                  password: str,
                  group_sAMAccountName: str = None,
                  verbose_logs: bool = False) -> bool | dict:
        """
        Authenticate LDAP user, mostly used for frontend apps
        :param user: LDAP login
        :param password: LDAP password
        :param group_sAMAccountName: The sAMAccountName of the group
        :param verbose_logs: A toggle between verbose and concise logs
        :return: True or False if verbose_logs is set to False, else a dictionary with verbose logs
        """
        user: str = user.split("@")[0] if "@" in user else user
        try:
            user_distinguishedName: str = self.get_user(sAMAccountName=user,
                                                        attributes=["distinguishedName"])["distinguishedName"]
            try:
                self.ldap_connection.rebind(user=user_distinguishedName, password=password)
                login_result = {"login": True,
                                "backend_log": f"'{user}' logged in",
                                "frontend_log": "Welcome"}
            except ldap3.core.exceptions.LDAPPasswordIsMandatoryError:
                login_result = {"login": False,
                                "backend_log": f"'{user}' tried to log in (provided no password)",
                                "frontend_log": "Authentication failed"}
            except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
                login_result = {"login": False,
                                "backend_log": f"'{user}' tried to log in (provided wrong password)",
                                "frontend_log": "Authentication failed"}
            finally:
                self.ldap_connection.bind()
        except ValueError:
            login_result = {"login": False,
                            "backend_log": f"'{user}' tried to log in (user doesn't exist in AD)",
                            "frontend_log": "Authentication failed"}
        return login_result if verbose_logs else login_result["login"]

    def modify_user(self,
                    sAMAccountName: str,
                    attributes: dict) -> list[dict]:
        """
        Change the attributes of a specfic user
        :param sAMAccountName: The login of the user
        :param attributes: A dictionary with new attributes and their values
        :return: A list of dictionaries with result logs
        :raises IndexError: If some attribute can't be added or changed
        """
        user_distinguishedName: str = self.get_user(sAMAccountName=sAMAccountName,
                                                    attributes=["distinguishedName"])["distinguishedName"]
        ldap_connection: ldap3.Connection = self.connect_to_ldap()
        result: list[dict] = []
        for attribute, value in attributes.items():
            try:
                ldap_connection.modify(dn=user_distinguishedName,
                                       changes={attribute: [(ldap3.MODIFY_ADD, [value])]})
            except ldap3.core.exceptions.LDAPAttributeOrValueExistsResult:
                try:
                    ldap_connection.modify(dn=user_distinguishedName,
                                           changes={attribute: [(ldap3.MODIFY_REPLACE, [value])]})
                except ldap3.core.exceptions.LDAPUnwillingToPerformResult:
                    raise IndexError(f"'{attribute}' attribute can only be added/changed after a password change")
            result.append(ldap_connection.result)
        return result

    def change_user_password(self,
                             sAMAccountName: str,
                             new_password: str) -> dict:
        """
        Change LDAP password of a specific user
        :param sAMAccountName: The login of the user
        :param new_password: new LDAP password
        :return: A dictionary with result logs
        :raises IndexError: If new_password is invalid
        """
        user_distinguishedName: str = self.get_user(sAMAccountName=sAMAccountName,
                                                    attributes=["distinguishedName"])["distinguishedName"]
        ldap_connection: ldap3.Connection = self.connect_to_ldap()
        try:
            ldap_connection.extend.microsoft.modify_password(user_distinguishedName,
                                                             new_password)
            return ldap_connection.result
        except ldap3.core.exceptions.LDAPUnwillingToPerformResult:
            raise IndexError("New password must contain at least 8 characters, include a digit and uppercase and lowercase letter")

    def delete_user(self,
                    sAMAccountName: str) -> dict:
        """
        Delete specific user
        :param sAMAccountName: The login of the user
        :return: A dictionary with result logs
        """
        user_distinguishedName: str = self.get_user(sAMAccountName=sAMAccountName,
                                                    attributes=["distinguishedName"])["distinguishedName"]
        ldap_connection: ldap3.Connection = self.connect_to_ldap()
        ldap_connection.delete(dn=user_distinguishedName)
        return ldap_connection.result

    def add_group(self,
                  attributes: dict) -> dict:
        pass

    def get_all_groups(self,
                       attributes: list[str] = None,
                       search_filter: str = "(objectClass=group)") -> list[dict]:
        """
        Get the attributes of all groups
        :param attributes: A list of attributes to get, use ["*"] for all attributes
        :param search_filter: A filter for searching groups
        :return: A list of dictionaries with selected attributes
        """
        attributes: list[str] = attributes or ["sAMAccountName"]
        ldap_connection: ldap3.Connection = self.connect_to_ldap()
        ldap_connection.search(search_base=self.groups_ou,
                               search_filter=search_filter,
                               attributes=attributes)
        groups_attributes: list[dict] = json.loads(ldap_connection.response_to_json())["entries"]
        return [group["attributes"] for group in groups_attributes]

    def get_group(self,
                  sAMAccountName: str,
                  attributes: list[str] = None) -> dict:
        """
        Get the attributes of a specific group
        :param sAMAccountName: The sAMAccountName of the group
        :param attributes: A list of attributes to get, use ["*"] for all attributes
        :return: A dictionary with selected attributes
        :raises IndexError: If the group does not exist
        """
        attributes: list[str] = attributes or ["sAMAccountName"]
        ldap_connection: ldap3.Connection = self.connect_to_ldap()
        ldap_connection.search(search_base=self.groups_ou,
                               search_filter=f"(sAMAccountName={sAMAccountName})",
                               attributes=attributes)
        try:
            group_attributes: dict = json.loads(ldap_connection.response_to_json())["entries"][0]["attributes"]
            return group_attributes
        except IndexError:
            raise IndexError(f"Group '{sAMAccountName}' doesn't exist")

    def modify_group(self,
                     sAMAccountName: str,
                     attributes: dict) -> list[dict]:
        """
        Change the attributes of a specfic group
        :param sAMAccountName: The sAMAccountName of the group
        :param attributes: A dictionary with new attributes and their values
        :return: A list of dictionaries with result logs
        :raises IndexError: If some attribute can't be added or changed
        """
        pass

    def add_user_to_group(self,
                          user_sAMAccountName: str,
                          group_sAMAccountName: str) -> dict:
        """
        Add a specific user to a specific group
        :param user_sAMAccountName: The login of the user
        :param group_sAMAccountName: The sAMAccountName of the group
        :return: A dictionary with result logs
        :raises IndexError: If user is already in group
        """
        user_distinguishedName: str = self.get_user(sAMAccountName=user_sAMAccountName,
                                                    attributes=["distinguishedName"])["distinguishedName"]
        group_distinguishedName: str = self.get_group(sAMAccountName=group_sAMAccountName,
                                                      attributes=["distinguishedName"])["distinguishedName"]
        ldap_connection: ldap3.Connection = self.connect_to_ldap()
        try:
            ldap_connection.modify(dn=group_distinguishedName,
                                   changes={"member": [(ldap3.MODIFY_ADD, [user_distinguishedName])]})
            return ldap_connection.result
        except ldap3.core.exceptions.LDAPEntryAlreadyExistsResult:
            raise IndexError(f"User '{user_sAMAccountName}' is already in group '{group_sAMAccountName}'")

    def delete_user_from_group(self,
                               user_sAMAccountName: str,
                               group_sAMAccountName: str) -> dict:
        """
        Delete a specific user from a specific group
        :param user_sAMAccountName: The login of the user
        :param group_sAMAccountName: The sAMAccountName of the group
        :return: A dictionary with result logs
        :raises IndexError: If user is not in group
        """
        user_distinguishedName: str = self.get_user(sAMAccountName=user_sAMAccountName,
                                                    attributes=["distinguishedName"])["distinguishedName"]
        group_distinguishedName: str = self.get_group(sAMAccountName=group_sAMAccountName,
                                                      attributes=["distinguishedName"])["distinguishedName"]
        ldap_connection: ldap3.Connection = self.connect_to_ldap()
        try:
            ldap_connection.modify(dn=group_distinguishedName,
                                   changes={"member": [(ldap3.MODIFY_DELETE, [user_distinguishedName])]})
            return ldap_connection.result
        except ldap3.core.exceptions.LDAPUnwillingToPerformResult:
            raise IndexError(f"User '{user_sAMAccountName}' is not in group'{group_sAMAccountName}'")

    def delete_group(self,
                     sAMAccountName: str) -> dict:
        """
        Delete specific group
        :param sAMAccountName: The sAMAccountName of the group
        :return: A dictionary with result logs
        """
        pass
