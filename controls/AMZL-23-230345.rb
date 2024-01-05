control 'AMZL-23-230345' do
  title 'Amazon Linux 2023 must include root when automatically locking an account until
the locked account is released by an administrator when three unsuccessful
logon attempts occur during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    In Amazon Linux 2023.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module.  Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

    From "faillock.conf" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.'
  desc 'check', 'Note: This check applies to Amazon Linux versions 2023.2 or newer, if the system is
Amazon Linux version 2023.0 or 2023.1, this check is not applicable.

    Verify the "/etc/security/faillock.conf" file is configured to log user
name information when unsuccessful logon attempts occur:

    $ sudo grep even_deny_root /etc/security/faillock.conf

    even_deny_root

    If the "even_deny_root" option is not set, is missing or commented out,
this is a finding.'
  desc 'fix', 'Configure the operating system to include root when locking an account
after three unsuccessful logon attempts occur in 15 minutes.

    Add/Modify the "/etc/security/faillock.conf" file to match the following
line:

    even_deny_root'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'AMZL-23-230345'
  tag rid: 'AMZL-23-230345r743984_rule'
  tag stig_id: 'AMZL-23-020023'
  tag fix_id: 'F-32989r743983_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  describe parse_config_file('/etc/security/faillock.conf') do
    its('even_deny_root') { should_not be nil }
  end
  
end
