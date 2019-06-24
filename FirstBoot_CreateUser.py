#!/usr/bin/python
# The purpose of this script is to create or update a user account's password
# and FV unlock status on macOS 10.12 or higher using Jamf Pro.
# Script has been tested on 10.12.6 and 10.13.6 and 10.14.0.
#
# Because the purpose is to ensure that passwords are encrypted in delivery,
# this script makes use of:
# https://github.com/jamfit/Encrypted-Script-Parameters
# That means that whenever a password is being used:
# 1. an encrypted string needs to be generated and used in the appropriate Jamf
# parameter, and
# 2. a salt and passphrase which must be referenced inside the script.
# Python wrapper for 'openssl' to create an encrypted Base64 string for script
# parameters
# Additional layer of security when passing account credentials from the JSS to
# a client
#
# This script makes use of Jamf parameters. Below are instructions that
# indicate what Jamf parameters should be used and labeled as:
# Parameter 4: Required. Possible values without quotes:
#   "create-std,fv-disable" would create a new standard account without
#       FileVault unlock access.
#   "create-std,fv-enable" would create a new standard account with FileVault
#       unlock access.
#   "create-admin,fv-disable" would create a new administrator account without
#       FileVault unlock access.
#   "create-admin,fv-enable" would create a new administrator account with
#       FileVault unlock access.
#   "update,fv-disable" will update the password for targeted user and disable
#       their FileVault unlock access.
#   "update,fv-enable" will update the password for targeted user and enable
#       their FileVault unlock access.
# Depending on the user action value, the following parameters may be required
#   or optional.
# Parameter 5: Required for "create" and "update". The user name of the new
#   account you want to create.
# Parameter 6: Required for "create" only. The full name of the new account
#   you want to create.
# Parameter 7: Required for "create" and "update". The encrypted password
#   string of the new account you want to create.
#   See Encrypted Script Parameters for more details.
# Parameter 8: Optional for "create" only. The UID of the new account you want
#   to create. This must be an integer.
# Parameter 9: Required for "update". The new encrypted password string of
#   the account whose password you want to update.
# Parameter 10: Required for 10.13+ for "create" and "update". The existing
#   username of an account with a secure token.
# Parameter 11: Required for 10.13+ for "create" and "update". The encrypted
#   password string of an account with a secure token.
#   See Encrypted Script Parameters for more details.
#
# This script also has exit codes which may identify what error was
# encountered:
# 11: A required Jamf parameter is missing.
# 12: The UID is not an integer.
# 13: The UID is already in use.
# 14: Username is already in use.
# 15: The provided password for the existing user account could not be
#       verified.
# 16: The user's current password cannot be verified.
# 17: Incorrect value(s) for user action was entered (Jamf Parameter 4).
# 18: Error when providing secure token to user.
# 19: FileVault is not reporting as completely On.
# 20: FileVault could not output a list of users who can unlock drive.
# 21: Existing user does not have a secure token to be able to pass token to
#       another user.
# 22: 10.14+ requires password of 4 characters minimum. Password is too short.
# 23: Failed to update APFS Preboot volume.
# 24: Failed to decrypt password string
# 25: Failed to retrieve all users from dscl.
# 26: Failed to add user to FV unlock list.
# 27: Failed to remove user from FV unlock list.
# 28: Python could not decode decrypted string. Make sure your string,
#       salt, and passphrase match are correct.
# 29: The username of new user does not match that of the existing user.
#       Make sure both usernames match.
# 30: The existing user is not part of the FV user unlock list.
# 31: Error when running sysadminctl cli to pass secure token.
# 50: dscl returned an error
# 51: "guest" is a special reserved username.
# 52: Failed to add user to administrator group.


import subprocess
import os
import sys
import plistlib
import datetime
import textwrap
from distutils.version import StrictVersion


def exit_script(int):
    print("Script Exit Code: {}").format(int)
    sys.exit(int)


def check_return_output(rc, cli_tool, std_err, std_out, print_stdout=True):
    """
    Requires the returncode of a command, the name of said command line tool,
    and the stderr value.
    Returns the standard error output of a command.
    """
    if rc != 0 or std_err:
        print("{} has encountered an error.").format(cli_tool)
        print("{} STDERR:\n{}").format(cli_tool, std_err)
        print("Exit Code for {}: {}").format(cli_tool, rc)
        return rc
    if std_out and print_stdout:
        print("{} STDOUT:\n{}").format(cli_tool, std_out)
    return 0


class FS(object):
    """Class for the File System on current booted volume"""
    def get_os_ver(self):
        """Returns macOS version."""
        os_info = plistlib.readPlist(
                            "/System/Library/CoreServices/SystemVersion.plist")
        return os_info["ProductVersion"]

    def get_list_of_apfs_users(self):
        """
        Returns a list of all Generated UIDs recognized by the APFS volume.
        """
        cmd = ['/usr/sbin/diskutil', 'apfs', 'listUsers', '/', '-plist']

        ps = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE).communicate()[0]

        # Get results of diskutil in plist format
        plist_results = plistlib.readPlistFromString(ps)

        # Empty dictionary for GUIDs
        guid_list = []

        # Create a list of each APFS User's GUID
        for plist_key in plist_results["Users"]:
            guid_list.append(plist_key["APFSCryptoUserUUID"])
        return guid_list

    def get_user_guid(self, user):
        """Returns the user's Generated UID"""
        cmd = ['/usr/bin/dscl', '-plist', '/Local/Default', '-read',
               '/Users/' + user.username, 'GeneratedUID']
        ps = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE).communicate()[0]
        # Get results of dscl in plist format
        plist_results = plistlib.readPlistFromString(ps)
        # Get the user's Generated UID
        return plist_results["dsAttrTypeStandard:GeneratedUID"][0]

    def check_for_secure_token(self, user):
        """
        Check that the supplied username has a valid secure token.
        Returns Boolean: True if user has secure token and False if not.
        """
        # User's GUID
        user_guid = self.get_user_guid(user)
        # Loop through all current GUIDs to match passed username's GUID
        for apfs_guid in FS().get_list_of_apfs_users():
            if user_guid == apfs_guid:
                print("\'{}\' has a secure token.").format(user.username)
                return True
        print("\'{}\' does not have a secure token.").format(user.username)
        return False

    def get_user_home(self, user):
        """Returns user's home directory path."""
        cmd = ['/usr/bin/dscl', '-plist', '/Local/Default', '-read',
               '/Users/' + user.username, 'NFSHomeDirectory']
        ps = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE).communicate()[0]
        # Get results of diskutil in plist format
        plist_results = plistlib.readPlistFromString(ps)
        # Get the user's home directory path
        user_home = plist_results["dsAttrTypeStandard:NFSHomeDirectory"][0]
        return str(user_home)

    def get_filesystem(self):
        """Determine the file system of the current volume."""
        # diskutil info -plist /
        cmd = ['/usr/sbin/diskutil', 'info', '-plist', '/']
        ps = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE).communicate()[0]
        # Get results of diskutil in plist format
        plist_results = plistlib.readPlistFromString(ps)
        # Get the file system
        fs = plist_results["FilesystemType"]
        return fs

    def provide_secure_token(self, n_user, e_user):
        """Provide secure token to new account from existing account."""
        if not FS().check_for_secure_token(e_user):
            exit_script(18)

        cmd = ['/usr/sbin/sysadminctl', '-adminUser', e_user.username,
               '-adminPassword', e_user.decrypt_string(),
               '-secureTokenOn',
               n_user.username, '-password', n_user.decrypt_string()]

        ps = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE)

        stdout, stderr = ps.communicate()

        if check_return_output(ps.returncode, "sysadminctl", stderr,
                               stdout) != 0:
            print("Error when providing secure token to user.")
            exit_script(18)

    def update_Preboot(self):
        """Update APFS Preboot volume with new secure token users."""
        cmd = ['/usr/sbin/diskutil', 'apfs', 'updatePreboot', '/']
        ps = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE)
        stdout, stderr = ps.communicate()
        if check_return_output(ps.returncode, "diskutil", stderr,
                               stdout) != 0:
            print("Failed to update APFS Preboot volume.")
            exit_script(23)


class User(object):
    """Class for user"""
    # Attributes that a standard user account needs
    def __init__(self, username, fullname,
                 pw_string, salt, passphrase, uid, acct_type, fv_user):
        if username.lower() != "guest":
            self.username = username
        else:
            print("\'guest\' is a special reserved username.")
            exit_script(51)
        self.username = username
        self.fullname = fullname
        self.pw_string = pw_string
        self.salt = salt
        self.passphrase = passphrase
        self.uid = uid
        self.acct_type = acct_type
        self.fv_user = fv_user

        # If UID has not be specified then use next available UID over 500
        self.user_attributes = {
            "RealName": self.fullname,
            "NFSHomeDirectory": "/Users/" + self.username,
            "dsAttrTypeNative:_writers_unlockOptions": self.username,
            "dsAttrTypeNative:_writers_picture": self.username,
            "dsAttrTypeNative:_writers_jpegphoto": self.username,
            "dsAttrTypeNative:_writers_hint": self.username,
            "dsAttrTypeNative:_writers_UserCertificate": self.username,
            "dsAttrTypeNative:_writers_AvatarRepresentation": self.username,
            "AuthenticationHint": "",
            "dsAttrTypeNative:unlockOptions": "0",
            "dsAttrTypeNative:AvatarRepresentation": "",
            "Picture": "/Library/User Pictures/Nature/Earth.png",  # randomize
            "UniqueID": None,
            "PrimaryGroupID": "20"
            }

        if StrictVersion(FS().get_os_ver()) >= StrictVersion("10.15.0"):
            self.user_attributes["UserShell"] = "/bin/zsh"
        else:
            self.user_attributes["UserShell"] = "/bin/bash"

        if self.uid is not None:
            if len(self.uid) == 0:
                self.user_attributes["UniqueID"] = (
                                            self.find_next_available_uid())
            else:
                self.user_attributes["UniqueID"] = uid
                self.user_attributes["PrimaryGroupID"] = uid

    def uid_is_int(self):
        """
        Ensure that the UID is a valid integer.
        Returns True if uid is valid integer or False if invalid integer.
        """
        if isinstance(int(self.uid), int):
            print("The UID \'{}\' is an integer.").format(self.uid)
            return True
        else:
            print("The UID \'{}\' is not an integer.").format(self.uid)
            return False

    def decrypt_string(self):
        """
        Returns the decrypted string based on the encrypted string, salt, and
        passphrase.
        """
        ps = subprocess.Popen(['/usr/bin/openssl', 'enc', '-aes256', '-d',
                               '-a', '-A', '-S', self.salt, '-k',
                               self.passphrase],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        stdout, stderr = ps.communicate(self.pw_string)

        if check_return_output(ps.returncode, "openssl", stderr, stdout,
                               print_stdout=False) != 0:
            print("Failed to decrypt password for user \'{}\'."
                  ).format(self.username)
            exit_script(24)

        try:
            stdout.decode('ascii')
        except BaseException as e:
            print(e)
            print("Python could not decode decrypted string for user \'{}\'. "
                  "Make sure your string, salt, and passphrase match are "
                  "correct.").format(self.username)
            exit_script(28)

        return stdout

    def find_next_available_uid(self, starter_uid=501):
        if starter_uid < 501:
            starter_uid = 501

        # Empty list to store all UIDs
        list_of_uids = []

        # Retrieve all UIDs in plist format
        cmd = ['/usr/bin/dscl', '-plist', '/Local/Default', '-readall',
               '/Users']

        ps = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE)

        stdout, stderr = ps.communicate()

        if check_return_output(ps.returncode, "dscl", stderr, stdout,
                               print_stdout=False) != 0:
            print("Failed get list of all users.")
            exit_script(25)

        plist_results = plistlib.readPlistFromString(stdout)

        # Loop through all UIDs to store in a list
        for plist_key in plist_results:
            plist_value = plist_key.get("dsAttrTypeStandard:UniqueID")
            if plist_value is not None:
                for value in plist_value:
                    if value not in list_of_uids:
                        list_of_uids.append(int(value))

        list_of_uids_over_500 = [uid for uid in list_of_uids if uid > 500]

        # Determine the first available UID over 500
        while starter_uid in list_of_uids_over_500:
                starter_uid += 1
        return str(starter_uid)


def validate_pw_for_user(user):
    """
    Validate that the user account's password is valid.
    Returns 0 if successful or the exit code value if not successful.
    """
    cmd = ['/usr/bin/dscl', '/Search', '-authonly', user.username,
           user.decrypt_string()]
    ps = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = ps.communicate()
    if check_return_output(ps.returncode, "dscl", stderr, stdout) != 0:
        print("The current password for \'{}\' cannot be verified."
              ).format(user.username)
        exit(16)
    return 0


def validate_pw_length_for_user(user):
    """
    Validate that the user account's password is minimum 4 characters long.
    Returns True if minimum character length met otherwise returns False.
    """
    return len(user.decrypt_string()) >= 4


def check_against_existing_ds_values(ds_attribute, ds_value):
    """
    Check against existing records in the local directory service to
    prevent an error.
    Specifically meant to to prevent using already existing usernames
    (dsAttrTypeStandard:RecordName) and UIDs (dsAttrTypeStandard:UniqueID).
    Return Bool
    """
    # UID cannot be already in use
    # Username cannot be already in use
    # Find users and UIDs
    # dscl . -list /Users RecordName | sort -k 2 -numeric-sort
    # Gets me the 2nd column only but sorted
    # dscl . -list /Users RecordName | awk -F ' ' '{print $2}'
    # Gets me the 2nd column only unsorted
    # dscl -plist . -readall /Users RecordName
    # Gets me all attributes in plist format. Use plistb
    # plist results in a list
    # the entries are a dictionary e.g.:
    #   {'dsAttrTypeStandard:UniqueID': ['83'],
    #   'dsAttrTypeStandard:RecordName': ['_amavisd', 'amavisd']}
    # the key in in the dictionary entry is the attribute type from dscl e.g.:
    #   dsAttrTypeStandard:RecordName
    # the values for that are lists e.g. ['83']
    cmd = ['/usr/bin/dscl', '-plist', '/Local/Default', '-readall', '/Users']
    ps = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE).communicate()[0]
    # Get results of dscl in plist format
    plist_results = plistlib.readPlistFromString(ps)
    for plist_key in plist_results:
        plist_value = plist_key.get(ds_attribute, "0")
        for value in plist_value:
            if ds_value == value:
                print("The directory service attribute \'{}\' of \'{}\' is in "
                      "use.").format(str(ds_attribute).split(":")[1], ds_value)
                return True
    return False


class FV(object):
    """Class for FileVault on current booted volume"""
    def encode_xml(self, string, encoding='utf-8'):
        """
        Returns a string with any of the 5 special
        XML escape characters translated.
        """
        string = string.encode(encoding)
        string = string.replace('&', '&amp;')
        string = string.replace('<', '&lt;')
        string = string.replace('>', '&gt;')
        string = string.replace('"', '&quot;')
        string = string.replace("'", "&apos;")
        return string

    def check_fv_status(self):
        """Provide seucre token to new account."""
        cmd = ['/usr/bin/fdesetup', 'status']
        ps = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE)
        stdout = ps.communicate()[0]
        # print("The STDOUT is %s and the STDERR\
        #        is %s." % (str(stdout),str(stderr)))
        return stdout

    def get_user_list(self):
        """
        Check if user is a FileVault user who can unlock drive.
        Return dictionary of Username : Generated UID
        """
        cmd = ['/usr/bin/fdesetup', 'list']
        ps = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE)

        stdout, stderr = ps.communicate()

        if check_return_output(ps.returncode, "fdesetup", stderr, stdout) != 0:
            exit_script(20)

        # Split the list by newline
        fv_user_list = stdout.split("\n")

        # Remove the last entry in the list which is a blank entry
        fv_user_list.pop(-1)

        # Create a dictionary of Username : Generated UID
        fv_user_dict = {}

        for index in fv_user_list:
            fv_user_dict[index.split(",")[0]] = index.split(",")[1]

        return fv_user_dict

    def input(self, n_user, e_user):
        """Return STDIN xml for use with fdesetup."""
        fv_plist_data = {'Password': self.encode_xml(e_user.decrypt_string()),

                         'AdditionalUsers': [{'Username': n_user.username,
                                              'Password': self.encode_xml(
                                                n_user.decrypt_string())}]}
        input_plist = plistlib.writePlistToString(fv_plist_data)
        return input_plist

    def add_user(self, n_user, e_user):
        """Add user to FV unlock list."""
        print("Adding \'{}\' to the FV user list.").format(n_user.username)

        cmd = ['/usr/bin/fdesetup', 'add', '-inputplist']

        ps = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE)

        stdout, stderr = ps.communicate(input=self.input(n_user, e_user))

        if check_return_output(ps.returncode, "fdesetup", stderr, stdout) != 0:
            print("Could not remove user \'{}\' from FileVault unlock list."
                  ).format(n_user.username)
            exit_script(26)

        return 0

    def remove_user(self, n_user):
        """Remove user from FV unlock list"""
        print("Removing \'{}\' from the FV user list.").format(n_user.username)
        cmd = ['/usr/bin/fdesetup', 'remove', '-user', n_user.username]

        ps = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE)

        stdout, stderr = ps.communicate()

        if check_return_output(ps.returncode, "fdesetup", stderr, stdout) != 0:
            print("Could not remove user \'{}\' from FileVault unlock list."
                  ).format(n_user.username)
            exit_script(27)

        return 0


def archive_keychain(user):
    """Renames user's current keychain folder."""
    # Create a timestamp
    time_stamp = "{:%Y%m%d%H%M%S}".format(datetime.datetime.now())
    # Current path of user's Keychain folder
    keychain_original = FS().get_user_home(user) + "/Library/Keychains"
    # New path to backup the user's Keychain folder
    keychain_renamed = str(keychain_original) + "_" + str(time_stamp)
    # print("The original user's keychain folder is: {}.\nThe user's keychain\
    # folder has been moved to: {}").format(keychain_original,keychain_renamed)
    # Rename the user's Keychain folder
    os.rename(keychain_original, keychain_renamed)


def check_against_required_jamf_parameters(jamf_param):
    """
    Evaluate whether a Jamf parameter is populated.
    Returns Boolean: True if it's populated and False if not.
    """
    if len(jamf_param) > 0:
        return True
    else:
        return False


def cud_user_record(user, a_user=None, action="create", attr=None,
                    value=None):
    """
    Create Update Delete a user record using the directory service command line
    tool: dscl.
    user = User object
    a_user = Additional User object.
    action = Default value is: "create". Other values: "passwd", "delete"
    attr = User attribute for user account.
    value = User attribute's value for user account.
    """
    cmd = ['/usr/bin/dscl', '/Local/Default', action,
           '/Users/' + user.username]

    if action == "create" and attr is not None and value is not None:
        cmd += [attr, value]

    if action == "passwd":
        cmd += [user.decrypt_string()]
        if a_user is not None:
            cmd += [a_user.decrypt_string()]

    ps = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    stdout, stderr = ps.communicate()

    if check_return_output(ps.returncode, "dscl", stderr, stdout) != 0:
        exit_script(50)


def create_user(n_user, e_user):
    """Create a user account"""
    # Run some validation against certain parameters to avoid re-using existing
    # user attributes
    if check_against_required_jamf_parameters(n_user.uid):
        if not n_user.uid_is_int():
            exit_script(12)
        if check_against_existing_ds_values("dsAttrTypeStandard:UniqueID",
                                            n_user.uid):
            exit_script(13)
    if check_against_existing_ds_values("dsAttrTypeStandard:RecordName",
                                        n_user.username):
        print("Username \'{}\' is already in use. Consider using "
              "'update,fv-disable' or 'update,fv-enable' if you want to update"
              " a user's password.").format(n_user.username)
        exit_script(14)
    if (StrictVersion(FS().get_os_ver()) >= StrictVersion("10.14.0") and
       len(n_user.decrypt_string()) < 4):
        print("10.14+ requires password of 4 characters minimum. "
              "Password is too short.")
        exit_script(22)
    if (FS().get_filesystem() == "apfs" and
       not FS().check_for_secure_token(e_user) and n_user.fv_user == "yes"):
        # cud_user_record(user=n_user, action="delete")
        print("The existing user \'{}\' does not have a secure token. "
              "It cannot pass a token to \'{}\'. No action taken."
              ).format(e_user.username, n_user.username)
        exit_script(21)

    # Create a user record
    if StrictVersion(FS().get_os_ver()) >= StrictVersion("10.12.0"):
        cud_user_record(user=n_user, action="create")
        # Provide all user attributes to user record
        for attr, value in n_user.user_attributes.items():
            if attr not in ("UniqueID", "PrimaryGroupID"):
                cud_user_record(user=n_user, action="create", attr=attr,
                                value=value)
        # We want to apply the UID and PrimaryGroupID for the user for last
        cud_user_record(user=n_user, action="create", attr="UniqueID",
                        value=n_user.user_attributes["UniqueID"])
        cud_user_record(user=n_user, action="create", attr="PrimaryGroupID",
                        value=n_user.user_attributes["PrimaryGroupID"])
        # Provide the just created user record a password
        cud_user_record(user=n_user, action="passwd")
        # Provide user admin access
        if n_user.acct_type == "administrator":
            # There appear to be two groups that you do NOT get added to when
            # going through CLI compared to going through Sys Pref GUI:
            # 79(_appserverusr),81(_appserveradm)
            cmd = ['/usr/sbin/dseditgroup', '-o', 'edit', '-a',
                   n_user.username, '-t', 'user', 'admin']
            ps = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE)
            stdout, stderr = ps.communicate()
            if check_return_output(ps.returncode, "dseditgroup", stderr, stdout
                                   ) != 0:
                print("Failed to make user \'{}\' an administrator."
                      ).format(n_user.username)
                exit_script(52)

    # Provide user a secure token on AFPS
    if FS().get_filesystem() == "apfs":
        # Starting in 10.13, an account with a secure token is needed to create
        # another user with secure token.
        # /usr/sbin/sysadminctl -adminUser "$st_user" -adminPassword
        # "$st_pw" -secureTokenOn "$user" -password "$user_pw"
        # print("FS().check_for_secure_token(e_user):")
        # print(FS().check_for_secure_token(e_user))
        # print("n_user.fv_user:")
        # print(n_user.fv_user)
        if n_user.fv_user == "yes":
            print("Existing user \'{}\' has secure token. Providing \'{}\' "
                  "with a secure token.").format(e_user.username,
                                                 n_user.username)
            FS().provide_secure_token(n_user, e_user)

    # Get FV user list
    fv_list = FV().get_user_list()

    # Remove user from FV unlock list if they are not supposed to have
    # secure token. A safe guard in case new user gets added to FV unlock list.
    if n_user.fv_user == "no" and fv_list.get(n_user.username) is not None:
        FV().remove_user(n_user)

    # Add user to FileVault unlock list
    if n_user.fv_user == "yes" and fv_list.get(n_user.username) is None:
        FV().add_user(n_user, e_user)


def update_user(e_user, n_user):
    # Run some validation against certain parameters to avoid re-using existing
    # user attributes
    if (check_against_existing_ds_values("dsAttrTypeStandard:RecordName",
       e_user.username) is False):
        print("Username \'{}\' cannot be updated because it does not exist. "
              "Please consider creating the account by using: "
              "\'create-std,fv-disable\', \'create-std,fv-enable\', "
              "\'create-admin,fv-disable\', \'create-admin,fv-enable\'."
              ).format(n_user.username)
        exit_script(14)

    # Confirm that current user's password is good
    if validate_pw_for_user(e_user) != 0:
        print("Current password for \'{}\' is incorrect and cannot be updated."
              ).format(e_user.username)
        exit_script(16)

    # macOS 10.14+ requires a password of 4 characters minimum
    if (StrictVersion(FS().get_os_ver()) >= StrictVersion("10.14.0") and
       not validate_pw_length_for_user(n_user)):
        print("macOS 10.14+ has a minimum password length requirement "
              "of 4 characters. Password is too short.")
        exit_script(22)

    # Confirm that both usernames for the two user arguments match
    if e_user.username != n_user.username:
        print("The username of new user does not match that of the existing "
              "user. Make sure both usernames match and that the appropriate "
              "string, salt, and passphrase have been updated in the script.")
        exit_script(29)
    # elif (FS().get_filesystem() == "apfs" and
    #       not FS().check_for_secure_token(e_user) and n_user.fv_user == "yes"):
    #     # cud_user_record(user=n_user, action="delete")
    #     print("The existing user \'{}\' does not have a secure token. "
    #           "It cannot pass a token to \'{}\'.").format(e_user.username,
    #                                                       n_user.username)
    #     exit_script(21)
    # Run the appropriate dscl command based on the operating system and
    # parameters that have been filled.
    cud_user_record(user=e_user, a_user=n_user, action="passwd")
    # 10.13+ will automatically delete keychain when password is out of sync
    if StrictVersion(FS().get_os_ver()) < StrictVersion("10.13.0"):
        archive_keychain(e_user)
    # Update APFS preboot
    if FS().get_filesystem() == "apfs":
        FS().update_Preboot()
    # Provide user a secure token on AFPS
    # if FS().get_filesystem() == "apfs":
    #     # Starting in 10.13, an account with a secure token is needed to create
    #     # another user with secure token.
    #     # /usr/sbin/sysadminctl -adminUser "$st_user" -adminPassword
    #     # "$st_pw" -secureTokenOn "$user" -password "$user_pw"
    #     """
    #     Start troubleshooting here vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
    #     """
    #     if (n_user.fv_user == "yes" and
    #        FS().check_for_secure_token(e_user) is True and
    #        FS().check_for_secure_token(n_user) is False):
    #         print("Existing user \'{}\' has secure token. Providing \'{}\' "
    #               "with a secure token.").format(e_user.username,
    #                                              n_user.username)
    #         cmd = ['/usr/sbin/sysadminctl',
    #                '-adminUser', e_user.username,
    #                '-adminPassword', e_user.decrypt_string(),
    #                '-secureTokenOn', n_user.username,
    #                '-password', n_user.decrypt_string()]
    #         ps = subprocess.Popen(cmd, stdin=subprocess.PIPE,
    #                               stdout=subprocess.PIPE)
    #         stdout, stderr = ps.communicate()
    #         if (check_return_output(ps.returncode, "sysadminctl",
    #                                 stderr, stdout) != 0):
    #             exit_script(31)
    # # Get FV user list
    # fv_list = FV().get_user_list()
    # # Update FV user list
    # print("Checking whether user \'{}\' needs to be added to FV unlock list"
    #       ).format(n_user.username)
    # if n_user.fv_user == "no" and fv_list.get(n_user.username) is not None:
    #     FV().remove_user(n_user)
    #     FS().update_Preboot()
    # elif n_user.fv_user == "yes" and fv_list.get(n_user.username) is None:
    #     FV().add_user(a_user, e_user)
    #     FS().update_Preboot()
    # else:
    #     print("The user \'{}\' does not need to be added to FV unlock list."
    #           ).format(n_user.username)


def main():
    """Main routine"""
    # List of actions to take
    action_list = user_action.lower().split(",")

    # Creating a list of required Jamf parameters
    required_jamf_params = {"user_action": user_action,
                            "new_user.username": new_user.username,
                            "new_user.fullname": new_user.fullname,
                            "new_user.pw_string": new_user.pw_string}
    required_jamf_params_for_apfs = {"existing_user.username":
                                     existing_user.username,
                                     "existing_user.pw_string":
                                     existing_user.pw_string}

    # Removing "fullname" as a required Jamf parameter for the "update" action
    if action_list[0] == "update":
        del required_jamf_params["new_user.fullname"]

    # Ensure the required Jamf Parameters are populated depending on the
    # version of macOS this script is running on
    if (StrictVersion(FS().get_os_ver()) < StrictVersion("10.13.0") and
       StrictVersion(FS().get_os_ver()) >= StrictVersion("10.12.0")):
        for parameter, value in required_jamf_params.iteritems():
            if check_against_required_jamf_parameters(value) is False:
                print("The required Jamf parameter \'{}\' is missing. "
                      "Script is exiting.").format(parameter)
                exit_script(11)

    if FS().get_filesystem() == "apfs":
        for parameter, value in required_jamf_params_for_apfs.iteritems():
            if check_against_required_jamf_parameters(value) is False:
                print("The required Jamf parameter \'{}\' is missing. "
                      "Script is exiting.").format(parameter)
                exit_script(11)

    # Run some validation against certain parameters to ensure existing user
    # password is valid.
    if validate_pw_for_user(existing_user) != 0:
        print("The existing user admin password could not be validated.")
        exit_script(15)

    # Determine user action to take
    if len(action_list) != 2:
        print("Fill out User Action parameter correctly.")
        exit_script(17)

    if action_list[1] != "fv-enable" and action_list[1] != "fv-disable":
        print("Fill out User Action parameter correctly.")
        exit_script(17)

    new_user.fv_user = "yes" if action_list[1] == "fv-enable" else "no"

    action_table = {
        "create-std": ("create", "standard"),
        "create-admin": ("create", "administrator"),
        "update": ("update", None)
    }

    try:
        action_value = action_table[action_list[0]]
    except KeyError:
        print("Fill out User Action parameter correctly.")
        exit_script(17)

    action = action_value[0]
    if action_value[1]:
        new_user.acct_type = action_value[1]

    # Check FV status to ensure a user can be added as a FV unlock user
    status = FV().check_fv_status()
    if (new_user.fv_user == "yes" and
            status.split("\n")[0] != "FileVault is On."):
        print("You have selected user \'{}\' to be added to the FV unlock "
              "list. However FileVault is not On. No action to be taken."
              ).format(new_user.username)
        exit_script(19)
    elif (new_user.fv_user == "yes" and
            status.split("\n")[0] == "FileVault is On."):
        fv_user_list = FV().get_user_list()
        if (FS().get_user_guid(existing_user) !=
           fv_user_list.get(existing_user.username)):
            print("Existing user's \'{e_u}\' GUID \'{guid}\' is not a "
                  "FileVault unlock user. Must have an existing user who is "
                  "already a FileVault unlock user in order to add a new user."
                  ).format(e_u=existing_user.username,
                           guid=FS().get_user_guid(existing_user))
            exit_script(30)
    if action == "create":
        create_user(new_user, existing_user)
    elif action == "update":
        update_user(existing_user, new_user)
    else:
        print("Please specify 'create-admin', 'create-std', or 'update'\
              in respective Jamf parameter.")
        exit_script(17)


# The following attributes DO NOT need to be changed with the exception of:
# You need to generate a new salt and passphrase for each password in use.
# These are marked with the comment: # <<CHANGE VALUE
# See Encrypted Script Parameters for more details.

# For testing
# user_action = "update,fv-disable"
user_action = "create-admin,fv-enable"

# Variations of the user_action values you can use two lines above
# "create-std,fv-disable"
# "create-std,fv-enable"
# "create-admin,fv-disable"
# "create-admin,fv-enable"
# "update,fv-disable"
# "update,fv-enable"

# Password: 1234
new_user = User(username="test",  
                fullname="test",
                pw_string="U2FsdGVkX19XuOXZZzPZ8mR0SXm0yT7VfJGII0AFVaY=",
                salt="57b8e5d96733d9f2",  # <<CHANGE VALUE
                passphrase="eafca104911e70a413b67590",  # <<CHANGE VALUE
                uid="",
                acct_type="standard",
                fv_user="yes"
                )

# Password: 1
existing_user = User(username="user",
                     fullname=None,
                     pw_string="U2FsdGVkX18mo1tbMpn2J564eGVjnPeVw8TjVV1wf5g=",
                     salt="26a35b5b3299f627",  # <<CHANGE VALUE
                     passphrase="cc51650c8b89bb4fb6499d56",  # <<CHANGE VALUE
                     uid=None,
                     acct_type=None,
                     fv_user=None
                     )

# Password: 1
amended_user = User(username="user",
                    fullname=None,
                    pw_string="U2FsdGVkX18mo1tbMpn2J564eGVjnPeVw8TjVV1wf5g=",
                    salt="26a35b5b3299f627",  # <<CHANGE VALUE
                    passphrase="cc51650c8b89bb4fb6499d56",  # <<CHANGE VALUE
                    uid=None,
                    acct_type=None,
                    fv_user=None
                    )


if __name__ == '__main__':
    main()
