control 'AMZL-23-230221' do
  title "Amazon Linux 2023 must be a vendor-supported release."
  desc  "
    An operating system release is considered \"supported\" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.
    
    A new major version of Amazon Linux is released every two years and includes ﬁve years of support. Each release includes support in two phases. The standard support phase covers the first two years. Next, a maintenance phase continues support for an additional three years.
    
    In the standard support phase, the release receives quarterly minor version updates. During the maintenance phase, a release receives only security updates and critical bug ﬁxes that are published as soon as they're available.
    
    With every Amazon Linux release (major version, minor version, or a security release), AWS release a new Linux Amazon Machine Image (AMI).
    
    Major version release— Includes new features and improvements in security and performance across the stack. The improvements might include major changes to the kernel, toolchain, Glib C, OpenSSL, and any other system libraries and utilities. Major releases of Amazon Linux are based in part on the current version of the upstream Fedora Linux distribution. AWS might add or replace speciﬁc packages from other non-Fedora upstreams.
    
    Minor version release— A quarterly update that includes security updates, bug fixes, and new features and packages. Each minor version is a cumulative list of updates that includes security and bug fixes in addition to new features and packages. These releases might include latest language runtimes, such as PHP. They might also include other popular software packages such as Ansible and Docker.
  "
  desc  "rationale", ""
  desc  "check", "
    Verify the Amazon Linux 2023 release information by doing the following:
    
    cat /etc/os-release
    
    NAME=\"Amazon Linux\"
    VERSION=\"2023\"
    ID=\"amzn\"
    ID_LIKE=\"fedora\"
    VERSION_ID=\"2023\"
    PLATFORM_ID=\"platform:al2023\"
    PRETTY_NAME=\"Amazon Linux 2023\"
    ANSI_COLOR=\"0;33\"
    CPE_NAME=\"cpe:2.3:o:amazon:amazon_linux:2023\"
    HOME_URL=\"https://aws.amazon.com/linux/\"
    BUG_REPORT_URL=\"https://github.com/amazonlinux/amazon-linux-2023\"
    SUPPORT_END=\"2028-03-15\"
    
    If your date is beyond SUPPORT_END date, then this is a finding.
  "
  desc  "fix", "Upgrade to a supported version of Amazon Linux 2023."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'AMZL-23-230221'
  tag rid: 'AMZL-23-230221r743913_rule'
  tag stig_id: 'AMZL-23-010000'
  tag fix_id: 'F-32865r567410_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  release = os.release
  
  EOMS_DATE = case release
              when /^2023/
                '15 March 2028'
              end
  
  describe "The release \"#{release}\" must still be within the support window, ending #{EOMS_DATE}" do
    subject { Date.today <= Date.parse(EOMS_DATE) }
    it { should be true }
  end
end
