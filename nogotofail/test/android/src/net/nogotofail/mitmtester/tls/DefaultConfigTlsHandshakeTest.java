/*
 * Copyright 2014 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.nogotofail.mitmtester.tls;

import java.io.IOException;
import java.net.InetSocketAddress;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import net.nogotofail.mitmtester.BackgroundTest;
import net.nogotofail.mitmtester.util.TlsUtils;

/**
 * Test which performs a TLS/SSL handshake using the platform-default TLS/SSL configuration and reports the
 * resulting TLS/SSL protocol version and cipher suite. Chain-of-trust checking and hostname  verification is not
 * performed.
 */
public class DefaultConfigTlsHandshakeTest extends BackgroundTest {

  private static final String HOST = "www.google.com";

  @Override
  protected void runTest() throws Exception {
    SSLSocket sslSocket = null;
    try {
      SSLSocketFactory sslSocketFactory = TlsUtils.getTrustAllSSLSocketFactory();
      sslSocket = (SSLSocket) sslSocketFactory.createSocket();
      if (isDone()) {
        return;
      }
      setProgressMessage("Resolving address");
      InetSocketAddress address = new InetSocketAddress(HOST, 443);
      if (isDone()) {
        return;
      }
      setProgressMessage("Connecting to " + address);
      sslSocket.connect(address, 20 * 10000);
      if (isDone()) {
        return;
      }
      setProgressMessage("Performing TLS/SSL handshake");
      sslSocket.startHandshake();
      if (isDone()) {
        return;
      }
      SSLSession sslSession = sslSocket.getSession();
      setTestResult(sslSession.getProtocol() + " " + sslSession.getCipherSuite());
    } finally {
      if (sslSocket != null) {
        try {
          sslSocket.close();
        } catch (IOException ignored) {}
      }
    }
  }
}
