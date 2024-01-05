control 'AMZL-23-230258' do
  title 'Amazon Linux 2023 system commands must be owned by root.'
  desc 'If Amazon Linux 2023 were to allow any user to make changes to software
libraries, then those changes might be implemented without undergoing the
appropriate testing and approvals that are part of a robust change management
process.

    This requirement applies to Amazon Linux 2023 with software libraries that are
accessible and configurable, as in the case of interpreted languages. Software
libraries also include privileged programs that execute with escalated
privileges. Only qualified and authorized individuals will be allowed to obtain
access to information system components for purposes of initiating changes,
including upgrades and modifications.'
  desc 'check', 'Verify the system commands contained in the following directories are owned
by "root" with the following command:

    $ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin
! -user root -exec ls -l {} \\;

    If any system commands are returned, this is a finding.'
  desc 'fix', 'Configure the system commands to be protected from unauthorized access.

    Run the following command, replacing "[FILE]" with any system command
file not owned by "root".

    $ sudo chown root [FILE]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'AMZL-23-230258'
  tag rid: 'AMZL-23-230258r627750_rule'
  tag stig_id: 'AMZL-23-010310'
  tag fix_id: 'F-32902r567521_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  files = command('find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -exec ls -d {} \\;').stdout.split("\n")

  if files.empty?
    describe 'List of system commands not owned by root' do
      subject { files }
      it { should be_empty }
    end
  else
    files.each do |file|
      describe file(file) do
        it { should be_owned_by 'root' }
      end
    end
  end
end
