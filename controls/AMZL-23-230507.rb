control 'AMZL-23-230507' do
  title 'Amazon Linux 2023 Bluetooth must be disabled.'
  desc 'Without protection of communications with wireless peripherals,
confidentiality and integrity may be compromised because unprotected
communications can be intercepted and either read, altered, or used to
compromise the Amazon Linux 2023 operating system.

    This requirement applies to wireless peripheral technologies (e.g.,
wireless mice, keyboards, displays, etc.) used with Amazon Linux 2023 systems. Wireless
peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and
Near Field Communications [NFC]) present a unique challenge by creating an
open, unsecured port on a computer. Wireless peripherals must meet DoD
requirements for wireless data transmission and be approved for use by the
Authorizing Official (AO). Even though some wireless peripherals, such as mice
and pointing devices, do not ordinarily carry information that need to be
protected, modification of communications with these wireless peripherals may
be used to compromise the Amazon Linux 2023 operating system. Communication paths outside
the physical protection of a controlled boundary are exposed to the possibility
of interception and modification.

    Protecting the confidentiality and integrity of communications with
wireless peripherals can be accomplished by physical means (e.g., employing
physical barriers to wireless radio frequencies) or by logical means (e.g.,
employing cryptographic techniques). If physical means of protection are
employed, then logical means (cryptography) do not have to be employed, and
vice versa. If the wireless peripheral is only passing telemetry data,
encryption of the data may not be required.'
  desc 'check', 'If the device or operating system does not have a Bluetooth adapter
installed, this requirement is not applicable.

    This requirement is not applicable to mobile devices (smartphones and
tablets), where the use of Bluetooth is a local AO decision.

    Determine if Bluetooth is disabled with the following command:

    $ sudo grep bluetooth /etc/modprobe.d/*

    /etc/modprobe.d/bluetooth.conf:install bluetooth /bin/true

    If the Bluetooth driver blacklist entry is missing, a Bluetooth driver is
determined to be in use, and the collaborative computing device has not been
authorized for use, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the Bluetooth adapter when not in
use.

    Build or modify the "/etc/modprobe.d/bluetooth.conf" file with the
following line:

    install bluetooth /bin/true

    Reboot the system for the settings to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000300-GPOS-00118'
  tag gid: 'AMZL-23-230507'
  tag rid: 'AMZL-23-230507r627750_rule'
  tag stig_id: 'AMZL-23-040111'
  tag fix_id: 'F-33151r568268_fix'
  tag cci: ['CCI-001443']
  tag nist: ['AC-18 (1)']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  elsif input('bluetooth_installed')
    describe kernel_module('bluetooth') do
      it { should be_disabled }
      it { should be_blacklisted }
    end
  else
    impact 0.0
    describe 'Device or operating system does not have a Bluetooth adapter installed' do
      skip 'If the device or operating system does not have a Bluetooth adapter installed, this requirement is not applicable.'
    end
  end
end
