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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import net.nogotofail.mitmtester.BackgroundTest;
import net.nogotofail.mitmtester.util.TlsUtils;

/**
 * Test which issues an HTTPS GET request without requiring the server to authenticate itself (i.e., the client is
 * happy to use anonymous TLS/SSL cipher suites).
 */
public class NoTlsServerAutenticationRequiredTest extends BackgroundTest {

  private static final String HOST = "www.google.com";

  @Override
  protected void runTest() throws Exception {
    SSLSocket sslSocket = null;
    try {
      SSLSocketFactory sslSocketFactory = TlsUtils.getTrustAllSSLSocketFactory();
      sslSocket = (SSLSocket) sslSocketFactory.createSocket();
      TlsUtils.enableAnonymousCipherSuites(sslSocket);
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
      setProgressMessage("Sending application-level data");
      sslSocket.getOutputStream().write("GET / HTTP/1.0\r\n\r\n".getBytes("US-ASCII"));
      sslSocket.getOutputStream().flush();
      BufferedReader in = new BufferedReader(new InputStreamReader(sslSocket.getInputStream(), "ISO-8859-1"));
      String line = in.readLine();
      setTestResult(line);
    } finally {
      if (sslSocket != null) {
        try {
          sslSocket.close();
        } catch (IOException ignored) {}
      }
    }
  }
}
