control 'AMZL-23-230344' do
  title 'Amazon Linux 2023 must include root when automatically locking an account until
the locked account is released by an administrator when three unsuccessful
logon attempts occur during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    Amazon Linux 2023 can utilize the "pam_faillock.so" for this purpose. Note that
manual changes to the listed files may be overwritten by the "authselect"
program.

    From "Pam_Faillock" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.'
  desc 'check', 'Check that the system includes the root account when locking an account
after three unsuccessful logon attempts within a period of 15 minutes with the
following commands:

    Note: If the System Administrator demonstrates the use of an approved
centralized account management method that locks an account after three
unsuccessful logon attempts within a period of 15 minutes, this requirement is
not applicable.

    $ sudo grep pam_faillock.so /etc/pam.d/password-auth

    auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
deny=3 even_deny_root fail_interval=900 unlock_time=0
    auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
    account required pam_faillock.so

    If the "even_deny_root" option is missing from the "preauth" line with
the "pam_faillock.so" module, this is a finding.

    $ sudo grep pam_faillock.so /etc/pam.d/system-auth

    auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
deny=3 even_deny_root fail_interval=900 unlock_time=0
    auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
    account required pam_faillock.so

    If the "even_deny_root" option is missing from the "preauth" line with
the "pam_faillock.so" module, this is a finding.'
  desc 'fix', 'Configure the operating system to include root when locking an account
after three unsuccessful logon attempts occur in 15 minutes.

    Add/Modify the appropriate sections of the "/etc/pam.d/system-auth" and
"/etc/pam.d/password-auth" files to match the following lines:

    auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
deny=3 even_deny_root fail_interval=900 unlock_time=0
    auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
    account required pam_faillock.so

    The "sssd" service must be restarted for the changes to take effect. To
restart the "sssd" service, run the following command:

    $ sudo systemctl restart sssd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'AMZL-23-230344'
  tag rid: 'AMZL-23-230344r646874_rule'
  tag stig_id: 'AMZL-23-020022'
  tag fix_id: 'F-32988r567779_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  describe pam('/etc/pam.d/password-auth') do
    its('lines') { should match_pam_rule('auth [default=die]|required pam_faillock.so preauth').all_with_args('even_deny_root') }
  end
  describe pam('/etc/pam.d/system-auth') do
    its('lines') { should match_pam_rule('auth [default=die]|required pam_faillock.so preauth').all_with_args('even_deny_root') }
  end
end
