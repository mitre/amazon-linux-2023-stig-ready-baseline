control 'AMZL-23-230355' do
  title 'Amazon Linux 2023 must map the authenticated identity to the user or group
account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user
account, the ability to determine the identity of the individual user or group
will not be available for forensic analysis.

    There are various methods of mapping certificates to user/group accounts
for Amazon Linux 2023. For the purposes of this requirement, the check and fix will
account for Active Directory mapping. Some of the other possible methods
include joining the system to a domain and utilizing a Red Hat idM server, or a
local system mapping, where the system is not part of a domain.'
  desc 'check', 'Verify the certificate of the user or group is mapped to the corresponding
user or group in the "sssd.conf" file with the following command:

    $ sudo cat /etc/sssd/sssd.conf

    [sssd]
    config_file_version = 2
    services = pam, sudo, ssh
    domains = testing.test

    [pam]
    pam_cert_auth = True

    [domain/testing.test]
    id_provider = ldap

    [certmap/testing.test/rule_name]
    matchrule =<SAN>.*EDIPI@mil
    maprule = (userCertificate;binary={cert!bin})
    domains = testing.test

    If the certmap section does not exist, ask the System Administrator to
indicate how certificates are mapped to accounts.  If there is no evidence of
certificate mapping, this is a finding.'
  desc 'fix', 'Configure the operating system to map the authenticated identity to the
user or group account by adding or modifying the certmap section of the
"/etc/sssd/sssd.conf file based on the following example:

    [certmap/testing.test/rule_name]
    matchrule =<SAN>.*EDIPI@mil
    maprule = (userCertificate;binary={cert!bin})
    dmains = testing.test

    The "sssd" service must be restarted for the changes to take effect. To
restart the "sssd" service, run the following command:

    $ sudo systemctl restart sssd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag gid: 'AMZL-23-230355'
  tag rid: 'AMZL-23-230355r627750_rule'
  tag stig_id: 'AMZL-23-020090'
  tag fix_id: 'F-32999r567812_fix'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (c)']

  if virtualization.system.eql?('docker') && !file('/etc/sssd/sssd.conf').exist?
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe file('/etc/sssd/sssd.conf') do
      it { should exist }
      its('content') { should match /^[\s]*\[certmap.*\][\s]*$/ }
    end
  end
end
