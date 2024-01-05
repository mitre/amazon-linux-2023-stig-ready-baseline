control 'AMZL-23-245540' do
  title 'The Amazon Linux 2023 operating system must implement the Endpoint Security for
Linux Threat Prevention tool.'
  desc "Adding endpoint security tools can provide the capability to
automatically take actions in response to malicious behavior, which can provide
additional agility in reacting to network threats. These tools also often
include a reporting capability to provide network awareness of the system,
which may not otherwise exist in an organization's systems management regime."
  desc 'check', 'Per OPORD 16-0080, the preferred endpoint security tool is McAfee Endpoint
Security for Linux (ENSL) in conjunction with SELinux.

    Procedure:
    Check that the following package has been installed:

    $ sudo rpm -qa | grep -i mcafeetp

    If the "mcafeetp" package is not installed, this is a finding.

    Verify that the daemon is running:

    $ sudo ps -ef | grep -i mfetpd

    If the daemon is not running, this is a finding.'
  desc 'fix', 'Install and enable the latest McAfee ENSLTP package.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag gid: 'AMZL-23-245540'
  tag rid: 'AMZL-23-245540r754730_rule'
  tag stig_id: 'AMZL-23-010001'
  tag fix_id: 'F-48770r754729_fix'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    custom_antivirus = input('custom_antivirus')
    if !custom_antivirus
      describe package('mcafeetp') do
        it { should be_installed }
      end
      describe processes('mfetpd') do
        it { should exist }
      end
    else
      # Allow user to provide a description of their AV solution
      # for documentation.
      custom_antivirus_description = input('custom_antivirus_description')
      describe "Antivirus: #{custom_antivirus_description}" do
        subject { custom_antivirus_description }
        it { should_not cmp 'None' }
      end
    end
  end
end
