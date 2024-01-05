control 'AMZL-23-230486' do
  title 'Amazon Linux 2023 must disable network management of the chrony daemon.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and
can lead to an inaccurate analysis. Determining the correct time a particular
event occurred on a system is critical when conducting forensic analysis and
investigating system events. Sources outside the configured acceptable
allowance (drift) may be inaccurate.

    Not exposing the management interface of the chrony daemon on the network
diminishes the attack space.

    Amazon Linux 2023 utilizes the "timedatectl" command to view the status of the
"systemd-timesyncd.service". The "timedatectl" status will display the
local time, UTC, and the offset from UTC.

    Note that USNO offers authenticated NTP service to DoD and U.S. Government
agencies operating on the NIPR and SIPR networks. Visit
https://www.usno.navy.mil/USNO/time/ntp/dod-customers for more information.'
  desc 'check', %q(Verify Amazon Linux 2023 disables network management of the chrony daemon with the
following command:

    $ sudo grep -w 'cmdport' /etc/chrony.conf

    cmdport 0

    If the "cmdport" option is not set to "0", is commented out or missing,
this is a finding.)
  desc 'fix', 'Configure the operating system disable network management of the chrony
daemon by adding/modifying the following line in the /etc/chrony.conf file.

    cmdport 0'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'AMZL-23-230486'
  tag rid: 'AMZL-23-230486r627750_rule'
  tag stig_id: 'AMZL-23-030742'
  tag fix_id: 'F-33130r568205_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  if virtualization.system.eql?('docker') && !file('/etc/chrony.conf').exist?
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe ntp_conf('/etc/chrony.conf') do
      its('cmdport') { should cmp 0 }
    end
  end
end
