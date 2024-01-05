control 'AMZL-23-230339' do
  title 'Amazon Linux 2023 must ensure account lockouts persist.'
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
  desc 'check', %q(Note: This check applies to Amazon Linux versions 2023.2 or newer, if the system is
Amazon Linux version 2023.0 or 2023.1, this check is not applicable.

    Verify the "/etc/security/faillock.conf" file is configured use a
non-default faillock directory to ensure contents persist after reboot:

    $ sudo grep 'dir =' /etc/security/faillock.conf

    dir = /var/log/faillock

    If the "dir" option is not set to a non-default documented tally log
directory, is missing or commented out, this is a finding.)
  desc 'fix', 'Configure the operating system maintain the contents of the faillock
directory after a reboot.

    Add/Modify the "/etc/security/faillock.conf" file to match the following
line:

    dir = /var/log/faillock'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'AMZL-23-230339'
  tag rid: 'AMZL-23-230339r743975_rule'
  tag stig_id: 'AMZL-23-020017'
  tag fix_id: 'F-32983r743974_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  log_directory = input('log_directory')

  describe parse_config_file('/etc/security/faillock.conf') do
      its('dir') { should cmp log_directory }
  end
end
