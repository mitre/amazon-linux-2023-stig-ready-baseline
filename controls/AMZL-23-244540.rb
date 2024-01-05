control 'AMZL-23-244540' do
  title 'Amazon Linux 2023 must not allow blank or null passwords in the system-auth file.'
  desc 'If an account has an empty password, anyone could log on and run
commands with the privileges of that account. Accounts with empty passwords
should never be used in operational environments.'
  desc 'check', 'To verify that null passwords cannot be used, run the following command:

$ sudo grep -i nullok /etc/pam.d/system-auth

If output is produced, this is a finding.'
  desc 'fix', 'Remove any instances of the "nullok" option in the
"/etc/pam.d/system-auth" file to prevent logons with empty passwords.

    Note: Manual changes to the listed file may be overwritten by the
"authselect" program.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'AMZL-23-244540'
  tag rid: 'AMZL-23-244540r743869_rule'
  tag stig_id: 'AMZL-23-020331'
  tag fix_id: 'F-47772r743868_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('grep -i nullok /etc/pam.d/system-auth') do
    its('stdout.strip') { should be_empty }
  end
end
