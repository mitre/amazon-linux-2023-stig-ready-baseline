control 'AMZL-23-230247' do
  title 'The Amazon Linux 2023 /var/log/messages file must be group-owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the Amazon Linux 2023 system or platform. Additionally, Personally
Identifiable Information (PII) and operational information must not be revealed
through error messages to unauthorized personnel or their designated
representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements."
  desc 'check', 'Verify the "/var/log/messages" file is group-owned by root with the
following command:

    $ sudo stat -c "%G" /var/log/messages

    root

    If "root" is not returned as a result, this is a finding.'
  desc 'fix', 'Change the group of the file "/var/log/messages" to "root" by running
the following command:

    $ sudo chgrp root /var/log/messages'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'AMZL-23-230247'
  tag rid: 'AMZL-23-230247r627750_rule'
  tag stig_id: 'AMZL-23-010230'
  tag fix_id: 'F-32891r567488_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe file('/var/log/messages') do
    its('group') { should eq 'root' }
  end
end