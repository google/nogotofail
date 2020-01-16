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

package net.nogotofail.mitmtester.http;

import java.net.HttpURLConnection;
import java.net.URL;

import net.nogotofail.mitmtester.BackgroundTest;

public class CleartextHttpCredentialsTest extends BackgroundTest {

  private static final String TARGET = "http://www.google.com";

  @Override
  protected void runTest() throws Exception {
    HttpURLConnection connection = null;
    try {
      connection = (HttpURLConnection) new URL(TARGET).openConnection();
      connection.setConnectTimeout(20000);
      connection.setReadTimeout(20000);
      connection.setRequestProperty("Authorization", "value");
      setProgressMessage("Issuing HTTP request with Authorization header");
      setTestResult(connection.getResponseCode() + " " + connection.getResponseMessage());
    } finally {
      if (connection != null) {
        connection.disconnect();
      }
    }
  }
}
