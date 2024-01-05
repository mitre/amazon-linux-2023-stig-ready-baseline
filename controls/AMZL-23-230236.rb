control 'AMZL-23-230236' do
  title 'Amazon Linux 2023 operating systems must require authentication upon booting into
rescue mode.'
  desc 'If the system does not require valid root authentication before it
boots into emergency or rescue mode, anyone who invokes emergency or rescue
mode is granted privileged access to all files on the system.'
  desc 'check', 'Check to see if the system requires authentication for rescue mode with the
following command:

    $ sudo grep sulogin-shell /usr/lib/systemd/system/rescue.service

    ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue

    If the "ExecStart" line is configured for anything other than
"/usr/lib/systemd/systemd-sulogin-shell rescue", commented out, or missing,
this is a finding.'
  desc 'fix', 'Configure the system to require authentication upon booting into rescue
mode by adding the following line to the
"/usr/lib/systemd/system/rescue.service" file.

    ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag gid: 'AMZL-23-230236'
  tag rid: 'AMZL-23-230236r743928_rule'
  tag stig_id: 'AMZL-23-010151'
  tag fix_id: 'F-32880r743927_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe service('rescue') do
      its('params.ExecStart') { should include '/usr/lib/systemd/systemd-sulogin-shell rescue' }
    end
  end
end
