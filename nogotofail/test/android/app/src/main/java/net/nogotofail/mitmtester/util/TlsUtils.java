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

package net.nogotofail.mitmtester.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public class TlsUtils {
  private TlsUtils() {}

  public static void enableAnonymousCipherSuites(SSLSocket sslSocket) {
    List<String> enabledCipherSuites = new ArrayList<String>(Arrays.asList(sslSocket.getEnabledCipherSuites()));
    enabledCipherSuites.add("TLS_DH_anon_WITH_AES_128_CBC_SHA");
    enabledCipherSuites.add("TLS_ECDH_anon_WITH_AES_128_CBC_SHA");
    sslSocket.setEnabledCipherSuites(enabledCipherSuites.toArray(new String[enabledCipherSuites.size()]));
  }

  public static SSLSocketFactory getTrustAllSSLSocketFactory() {
    try {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(new KeyManager[0],
          new TrustManager[] { new AcceptAllX509TrustManager() }, null);
      return sslContext.getSocketFactory();
    } catch (Exception e) {
      throw new RuntimeException("Failed to create a trust-all SSLSocketFactory", e);
    }
  }
}
