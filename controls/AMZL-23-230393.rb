control 'AMZL-23-230393' do
  title 'The Amazon Linux 2023 audit system must audit local events.'
  desc 'Without establishing what type of events occurred, the source of
events, where events occurred, and the outcome of events, it would be difficult
to establish, correlate, and investigate the events leading up to an outage or
attack.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.'
  desc 'check', 'Verify the Amazon Linux 2023 Audit Daemon is configured to include local events, with
the following command:

    $ sudo grep local_events /etc/audit/auditd.conf

    local_events = yes

    If the value of the "local_events" option is not set to "yes", or the
line is commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to audit local events on the system.

Add or update the following line in "/etc/audit/auditd.conf" file:

local_events = yes'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'AMZL-23-230393'
  tag rid: 'AMZL-23-230393r627750_rule'
  tag stig_id: 'AMZL-23-030061'
  tag fix_id: 'F-33037r567926_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe parse_config_file('/etc/audit/auditd.conf') do
      its('local_events') { should eq 'yes' }
    end
  end
end
