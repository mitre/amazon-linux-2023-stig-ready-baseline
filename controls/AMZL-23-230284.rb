control 'AMZL-23-230284' do
  title 'There must be no .shosts files on the Amazon Linux 2023 operating system.'
  desc 'The ".shosts" files are used to configure host-based authentication
for individual users or the system via SSH. Host-based authentication is not
sufficient for preventing unauthorized access to the system, as it does not
require interactive identification and authentication of a connection request,
or for the use of two-factor authentication.'
  desc 'check', %q(Verify there are no ".shosts" files on Amazon Linux 2023 with the following command:

$ sudo find / -name '*.shosts'

If any ".shosts" files are found, this is a finding.)
  desc 'fix', 'Remove any found ".shosts" files from the system.

$ sudo rm /[path]/[to]/[file]/.shosts'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'AMZL-23-230284'
  tag rid: 'AMZL-23-230284r627750_rule'
  tag stig_id: 'AMZL-23-010470'
  tag fix_id: 'F-32928r567599_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('find / -xdev -xautofs -name .shosts') do
    its('stdout') { should be_empty }
  end
end
