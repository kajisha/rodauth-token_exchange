# frozen_string_literal: true

# Local reference topology only. NGINX=/absolute/path/nginx bundle exec ruby -Ilib script/verify_gateway.rb
require_relative "verify_tls"
require "tmpdir"
require "open3"

class TokenExchangeGatewayTest < TokenExchangeTlsTest
  undef_method :test_exchange_over_verified_tls

  def test_reference_gateway
    Timeout.timeout(40) do
      key = OpenSSL::PKey::RSA.new(2048)
      ca = certificate("Gateway test CA", key, nil, nil, true)
      server_key = OpenSSL::PKey::RSA.new(2048)
      cert = certificate("localhost", server_key, ca, key, false)
      context = OpenSSL::SSL::SSLContext.new
      context.cert, context.key = cert, server_key
      context.min_version = OpenSSL::SSL::TLS1_2_VERSION
      store = OpenSSL::X509::Store.new
      store.add_cert(ca)

      Dir.mktmpdir("token-exchange-gateway-") do |directory|
        File.write("#{directory}/server.pem", cert.to_pem)
        File.write("#{directory}/server.key", server_key.to_pem, perm: 0o600)
        File.write("#{directory}/upstream-ca.pem", ca.to_pem)
        check_headers = lambda do |headers|
          %w[forwarded x-forwarded-host x-forwarded-port x-forwarded-scheme x-forwarded-ssl front-end-https].each do |name|
            refute headers.key?(name), "Untrusted header reached upstream: #{name}"
          end
          assert_equal "localhost", headers["host"]
          assert_equal "https", headers["x-forwarded-proto"]
          assert_equal "127.0.0.1", headers["x-forwarded-for"]
        end
        with_server(context, requests: 6, inspect_headers: check_headers) do |upstream_port|
          with_gateway(directory, upstream_port) do |port|
            responses = 24.times.map do |index|
              gateway_request(port, store, index)
            end
            assert_equal 5, responses.count { |response| response.code == "200" }
            assert_equal 19, responses.count { |response| response.code == "429" }
            assert_equal 2, responses.map { |response| response["X-Probe-Worker"] }.uniq.size
            responses.select { |response| response.code == "200" }.each do |response|
              token = JSON.parse(response.body).fetch("access_token")
              assert @db[:oauth_grants].where(token: hash_token(token)).first
            end
            # Plain HTTP on the only listener must never reach the backend.
            plain = Net::HTTP.new("127.0.0.1", port, nil)
            plain.open_timeout = plain.read_timeout = 3
            assert_equal "400", plain.post("/token", "grant_type=#{GRANT}").code
            tcp = TCPSocket.new("127.0.0.1", port)
            obsolete = OpenSSL::SSL::SSLContext.new
            obsolete.security_level = 0
            obsolete.min_version = obsolete.max_version = OpenSSL::SSL::TLS1_1_VERSION
            socket = OpenSSL::SSL::SSLSocket.new(tcp, obsolete)
            socket.sync_close = true
            begin
              error = assert_raises(OpenSSL::SSL::SSLError) { socket.connect }
              assert_match(/protocol version/i, error.message)
            ensure
              socket.close
            end
            sleep 12.5 # One request replenishes at 5 requests/minute.
            assert_equal "200", gateway_request(port, store, 0).code
          end
        end

        # A trusted certificate with the wrong upstream hostname must fail closed.
        with_server(context, handshake_failure: :no_request) do |upstream_port|
          with_gateway(directory, upstream_port, upstream_name: "wrong.example") do |port|
            assert_equal "502", gateway_request(port, store, 0).code
          end
        end
        assert_includes File.read("#{directory}/error.log"), "does not match"

        other_key = OpenSSL::PKey::RSA.new(2048)
        other_ca = certificate("Unrelated CA", other_key, nil, nil, true)
        File.write("#{directory}/upstream-ca.pem", other_ca.to_pem)
        with_server(context, handshake_failure: :no_request) do |upstream_port|
          with_gateway(directory, upstream_port) do |port|
            assert_equal "502", gateway_request(port, store, 0).code
          end
        end
        assert_includes File.read("#{directory}/error.log"), "certificate verify error"
      end
    end
  end

  private

  def gateway_request(port, store, index)
    client = Net::HTTP.new("localhost", port, nil)
    client.use_ssl = true
    client.verify_mode = OpenSSL::SSL::VERIFY_PEER
    client.verify_hostname = true
    client.cert_store = store
    client.min_version = client.max_version = OpenSSL::SSL::TLS1_2_VERSION
    client.open_timeout = client.read_timeout = 3
    # Vary URI query, credentials and spoofed forwarding header without resetting quota.
    path = index < 5 ? "/token" : %w[/token /token/ /oauth/token //token][index % 4]
    request = Net::HTTP::Post.new("#{path}?attempt=#{index}")
    request.basic_auth(index < 5 ? "client" : "attacker-#{index}", "secret")
    request["X-Forwarded-For"] = "192.0.2.#{index + 1}"
    %w[Forwarded X-Forwarded-Host X-Forwarded-Port X-Forwarded-Scheme X-Forwarded-Ssl Front-End-Https].each do |name|
      request[name] = "untrusted.example"
    end
    request["X-Forwarded-Proto"] = "http"
    request.set_form_data(grant_type: GRANT, subject_token: "subject-token", subject_token_type: ACCESS)
    client.request(request)
  end

  def with_gateway(directory, upstream_port, upstream_name: "localhost")
    reservation = TCPServer.new("127.0.0.1", 0)
    port = reservation.addr[1]
    reservation.close
    nginx = File.expand_path(ENV.fetch("NGINX", "vendor/nginx-probe/root/usr/sbin/nginx"))
    config = File.read(File.expand_path("../examples/nginx-token-exchange.conf", __dir__))
    { "DIRECTORY" => directory, "PORT" => port, "UPSTREAM_PORT" => upstream_port,
      "UPSTREAM_NAME" => upstream_name }.each { |name, value| config.gsub!("@#{name}@", value.to_s) }
    # Diagnostic only: never expose worker PIDs in the reference deployment config.
    config.sub!("server {", 'server { add_header X-Probe-Worker $pid always;')
    path = "#{directory}/nginx.conf"
    File.write(path, config)
    output, status = Open3.capture2e(nginx, "-t", "-c", path, "-p", directory)
    assert status.success?, output
    pid = Process.spawn(nginx, "-c", path, "-p", directory, "-g", "daemon off;",
                        out: File::NULL, err: "#{directory}/stderr.log", pgroup: true)
    Timeout.timeout(3) do
      loop do
        begin
          TCPSocket.new("127.0.0.1", port).close
          break
        rescue Errno::ECONNREFUSED
          sleep 0.02
        end
      end
    end
    yield port
  ensure
    if pid
      begin
        Process.kill("QUIT", pid)
        Timeout.timeout(3) { Process.wait(pid) }
      rescue Timeout::Error
        Process.kill("KILL", -pid)
        Process.wait(pid)
      rescue Errno::ESRCH, Errno::ECHILD
        # Already reaped or failed during startup.
      end
    end
  end
end
