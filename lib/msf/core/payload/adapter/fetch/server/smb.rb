module Msf::Payload::Adapter::Fetch::Server::SMB

  def start_smb_server(srvport, srvhost)
     @rsock = Rex::Socket::Tcp.create(
      'LocalHost' => srvhost,
      'LocalPort' => srvport,
      'Comm' => _determine_server_comm(srvhost),
      'Server' => true,
      'Context' =>
        {
          'Msf' => framework,
          'MsfExploit' => self
        }
    )

    log_device = LogAdapter::LogDevice::Framework.new(framework)

    thread_factory = Proc.new do |server_client, &block|
      Rex::ThreadFactory.spawn("SMBServerClient(#{server_client.peerhost}->#{server_client.dispatcher.tcp_socket.localhost})", false, &block)
    end

    ntlm_provider = Msf::Exploit::Remote::SMB::Server::HashCapture::HashCaptureNTLMProvider.new(
      allow_anonymous: true,
      allow_guests: true,
      listener: self,
      ntlm_type3_status: nil
    )

    server = RubySMB::Server.new(
      server_sock: @rsock,
      gss_provider: ntlm_provider,
      logger: log_device,
      thread_factory: thread_factory
    )

    server.extend(Msf::Exploit::Remote::SMB::Server::ServiceMixin)
    server.on_client_connect_proc = Proc.new { |client|
      on_client_connect(client)
    }
    @service = server
    @service.start

    vprint_status("Starting SMB server on #{Rex::Socket.to_authority(srvhost, srvport)}")
  end

  def cleanup_smb_fetch_service(fetch_service)
    fetch_service.stop unless fetch_service.nil?
  end

  def fetch_protocol
    'SMB'
  end

  def start_smb_fetch_handler(srvport, srvhost, srvuri, srvexe)
    @fetch_service = start_smb_server(srvport, srvhost)
    if @fetch_service.nil?
      cleanup_handler
      fail_with(Msf::Exploit::Failure::BadConfig, "Fetch Handler failed to start on #{Rex::Socket.to_authority(srvhost, srvport)}\n #{e}")
    end

    virtual_disk = RubySMB::Server::Share::Provider::VirtualDisk.new('toteslegit')
    # the virtual disk expects the path to use the native File::SEPARATOR so normalize on that here
    virtual_disk.add_static_file(srvuri, srvexe)
    @fetch_service.add_share(virtual_disk)

    @fetch_service.register_file(srvuri, srvexe)
    @fetch_service.start
    @fetch_service
  end

end

