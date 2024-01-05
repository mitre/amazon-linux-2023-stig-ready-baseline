control 'AMZL-23-230251' do
  title 'The Amazon Linux 2023 SSH server must be configured to use only Message
Authentication Codes (MACs) employing FIPS 140-2 validated cryptographic hash
algorithms.'
  desc 'Without cryptographic integrity protections, information can be
altered by unauthorized users without detection.

    Remote access (e.g., RDP) is access to DoD nonpublic information systems by
an authorized user (or an information system) communicating through an
external, non-organization-controlled network. Remote access methods include,
for example, dial-up, broadband, and wireless.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the secret key used to generate the hash.

    Amazon Linux 2023 incorporates system-wide crypto policies by default. The SSH
configuration file has no effect on the ciphers, MACs, or algorithms unless
specifically defined in the /etc/sysconfig/sshd file. The employed algorithms
can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.

    The system will attempt to use the first hash presented by the client that
matches the server list. Listing the values "strongest to weakest" is a
method to ensure the use of the strongest hash available to secure the SSH
connection.'
  desc 'check', 'Verify the SSH server is configured to use only MACs employing FIPS 140-2-approved algorithms with the following command:

     $ sudo grep -i macs /etc/crypto-policies/back-ends/opensshserver.config

     MACs hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,hmac-sha2-512

If the MACs entries in the "opensshserver.config" file have any hashes other than shown here, the order differs from the example above, or they are missing or commented out, this is a finding.'
  desc 'fix', 'Configure the Amazon Linux 2023 SSH server to use only MACs employing FIPS 140-2-approved algorithms by updating the "/etc/crypto-policies/back-ends/opensshserver.config" file with the following line:

MACs hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,hmac-sha2-512

A reboot is required for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065']
  tag gid: 'AMZL-23-230251'
  tag rid: 'AMZL-23-230251r917870_rule'
  tag stig_id: 'AMZL-23-010290'
  tag fix_id: 'F-32895r917869_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized AMZL' do
      skip 'Control not applicable - SSH is not installed within containerized AMZL'
    end
  else
    describe sshd_config('/etc/crypto-policies/back-ends/opensshserver.config') do
      its('MACs') { should include('hmac-sha2-256-etm@openssh.com') }
      its('MACs') { should include('hmac-sha1-etm@openssh.com') }
      its('MACs') { should include('hmac-sha2-512-etm@openssh.com') }
      its('MACs') { should include('hmac-sha2-256') }
      its('MACs') { should include('hmac-sha1') }
      its('MACs') { should include('hmac-sha2-512') }
    end
  end
end
