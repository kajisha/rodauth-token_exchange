# frozen_string_literal: true

# Local transport proof only; deployment TLS/proxy configuration needs its own check.
# Run: bundle exec ruby -Ilib script/verify_tls.rb
require_relative "../test/test_helper"
require "net/http"
require "openssl"
require "socket"
require "timeout"

class TokenExchangeTlsTest < ExchangeTest
  def test_exchange_over_verified_tls
    Timeout.timeout(20) do
      ca_key = OpenSSL::PKey::RSA.new(2048)
      ca = certificate("Local test CA", ca_key, nil, nil, true)
      server_key = OpenSSL::PKey::RSA.new(2048)
      server_cert = certificate("localhost", server_key, ca, ca_key, false)
      context = OpenSSL::SSL::SSLContext.new
      context.cert = server_cert
      context.key = server_key
      context.min_version = OpenSSL::SSL::TLS1_2_VERSION
      trusted = OpenSSL::X509::Store.new
      trusted.add_cert(ca)

      with_server(context) do |port|
        response = request(port, "localhost", trusted)
        assert_equal "200", response.code, response.body
        payload = JSON.parse(response.body)
        assert_equal ACCESS, payload.fetch("issued_token_type")
        assert_equal "bearer", payload.fetch("token_type").downcase
        token = payload.fetch("access_token")
        refute_empty token
        assert @db[:oauth_grants].where(token: hash_token(token)).first
      end

      # Both certificate-chain and hostname validation must actually reject peers.
      with_server(context, handshake_failure: true) do |port|
        error = assert_raises(OpenSSL::SSL::SSLError) do
          request(port, "localhost", OpenSSL::X509::Store.new)
        end
        assert_match(/certificate verify failed/i, error.message)
      end
      # Some clients reject hostnames after the TLS handshake. In either case,
      # credentials must never be sent to the mismatched peer.
      with_server(context, handshake_failure: :no_request) do |port|
        error = assert_raises(OpenSSL::SSL::SSLError) { request(port, "127.0.0.1", trusted) }
        assert_match(/hostname mismatch|hostname .* does not match the server certificate/i, error.message)
      end

      expired = certificate("localhost", server_key, ca, ca_key, false)
      expired.not_before = Time.now - 3600
      expired.not_after = Time.now - 60
      expired.sign(ca_key, OpenSSL::Digest::SHA256.new)
      expired_context = OpenSSL::SSL::SSLContext.new
      expired_context.cert, expired_context.key = expired, server_key
      expired_context.min_version = OpenSSL::SSL::TLS1_2_VERSION
      with_server(expired_context, handshake_failure: true) do |port|
        error = assert_raises(OpenSSL::SSL::SSLError) { request(port, "localhost", trusted) }
        assert_match(/certificate has expired/i, error.message)
      end
    end
  end

  private

  def certificate(name, key, issuer, issuer_key, ca)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = ca ? 1 : 2
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{name}")
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer || cert
    cert.add_extension(factory.create_extension("basicConstraints", ca ? "CA:TRUE" : "CA:FALSE", true))
    cert.add_extension(factory.create_extension("keyUsage", ca ? "keyCertSign,cRLSign" : "digitalSignature,keyEncipherment", true))
    unless ca
      cert.add_extension(factory.create_extension("extendedKeyUsage", "serverAuth"))
      cert.add_extension(factory.create_extension("subjectAltName", "DNS:localhost"))
    end
    cert.sign(issuer_key || key, OpenSSL::Digest::SHA256.new)
  end

  def request(port, hostname, store)
    # Disable environment proxies for the loopback probe.
    client = Net::HTTP.new(hostname, port, nil)
    client.use_ssl = true
    client.verify_mode = OpenSSL::SSL::VERIFY_PEER
    client.verify_hostname = true
    client.cert_store = store
    client.open_timeout = 3
    client.read_timeout = 3
    post = Net::HTTP::Post.new("/token")
    post.basic_auth("client", "secret")
    post.set_form_data(grant_type: GRANT, subject_token: "subject-token", subject_token_type: ACCESS)
    client.request(post)
  end

  def with_server(context, handshake_failure: false, requests: 1, inspect_headers: nil)
    listener = TCPServer.new("127.0.0.1", 0)
    ssl_server = OpenSSL::SSL::SSLServer.new(listener, context)
    thread = Thread.new do
      requests.times do
        socket = ssl_server.accept
        if handshake_failure == :no_request
          raise "Rejected upstream received a request" if socket.gets

          next
        end
        raise "Unexpected successful TLS handshake" if handshake_failure

        method, path, = socket.gets("\r\n", 8192).split(" ")
        headers = {}
        32.times do
          line = socket.gets("\r\n", 8192)
          break if line == "\r\n"

          key, value = line.split(":", 2)
          headers[key.downcase] = value.strip
        end
        inspect_headers&.call(headers)
        length = Integer(headers.fetch("content-length"))
        raise "Oversized probe request" unless length.between?(1, 8192)

        env = Rack::MockRequest.env_for("https://localhost#{path}", method: method,
                                      input: socket.read(length),
                                      "CONTENT_TYPE" => headers.fetch("content-type"),
                                      "HTTP_AUTHORIZATION" => headers.fetch("authorization"))
        raise "Incorrect transport scheme" unless env.fetch("rack.url_scheme") == "https"

        status, response_headers, response_body = app.call(env)
        payload = +""
        response_body.each { |part| payload << part }
        socket.write("HTTP/1.1 #{status} Response\r\n")
        response_headers.each do |key, value|
          next if %w[content-length connection].include?(key.downcase)

          socket.write("#{key}: #{value}\r\n")
        end
        socket.write("Content-Length: #{payload.bytesize}\r\nConnection: close\r\n\r\n#{payload}")
      rescue OpenSSL::SSL::SSLError
        raise unless handshake_failure
      ensure
        response_body.close if response_body.respond_to?(:close)
        socket&.close
      end
    end
    thread.report_on_exception = false
    yield listener.addr[1]
    raise "TLS server did not finish" unless thread.join(3)

    thread.value
  ensure
    listener&.close
    if thread&.alive?
      thread.kill
      thread.join
    end
  end
end
