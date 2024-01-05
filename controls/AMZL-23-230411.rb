control 'AMZL-23-230411' do
  title 'The Amazon Linux 2023 audit package must be installed.'
  desc 'Without establishing what type of events occurred, the source of
events, where events occurred, and the outcome of events, it would be difficult
to establish, correlate, and investigate the events leading up to an outage or
attack.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.

    Associating event types with detected events in Amazon Linux 2023 audit logs provides
a means of investigating an attack, recognizing resource utilization or
capacity thresholds, or identifying an improperly configured Amazon Linux 2023 system.'
  desc 'check', 'Verify the audit service is configured to produce audit records.

Check that the audit service is installed with the following command:

$ sudo yum list installed audit

If the "audit" package is not installed, this is a finding.'
  desc 'fix', 'Configure the audit service to produce audit records containing the
information needed to establish when (date and time) an event occurred.

    Install the audit service (if the audit service is not already installed)
with the following command:

    $ sudo yum install audit'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000051-GPOS-00024', 'SRG-OS-000054-GPOS-00025', 'SRG-OS-000122-GPOS-00063', 'SRG-OS-000254-GPOS-00095', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000337-GPOS-00129', 'SRG-OS-000348-GPOS-00136', 'SRG-OS-000349-GPOS-00137', 'SRG-OS-000350-GPOS-00138', 'SRG-OS-000351-GPOS-00139', 'SRG-OS-000352-GPOS-00140', 'SRG-OS-000353-GPOS-00141', 'SRG-OS-000354-GPOS-00142', 'SRG-OS-000358-GPOS-00145', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000475-GPOS-00220']
  tag gid: 'AMZL-23-230411'
  tag rid: 'AMZL-23-230411r744000_rule'
  tag stig_id: 'AMZL-23-030180'
  tag fix_id: 'F-33055r646880_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe package('audit') do
      it { should be_installed }
    end
  end
end