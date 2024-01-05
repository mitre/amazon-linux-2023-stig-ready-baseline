control 'AMZL-23-230381' do
  title 'Amazon Linux 2023 must display the date and time of the last successful account
logon upon logon.'
  desc 'Providing users with feedback on when account accesses last occurred
facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'Verify users are provided with feedback on when account accesses last
occurred with the following command:

    $ sudo grep pam_lastlog /etc/pam.d/postlogin

    session required pam_lastlog.so showfailed

    If "pam_lastlog" is missing from "/etc/pam.d/postlogin" file, or the
silent option is present, this is a finding.'
  desc 'fix', 'Configure the operating system to provide users with feedback on when
account accesses last occurred by setting the required configuration options in
"/etc/pam.d/postlogin".

    Add the following line to the top of "/etc/pam.d/postlogin":

    session required pam_lastlog.so showfailed'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'AMZL-23-230381'
  tag rid: 'AMZL-23-230381r627750_rule'
  tag stig_id: 'AMZL-23-020340'
  tag fix_id: 'F-33025r567890_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/pam.d/postlogin') do
    its('content') { should match /session\s+required\s+pam_lastlog\.so\s+showfailed/ }
  end
end
