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

import net.nogotofail.mitmtester.R;
import net.nogotofail.mitmtester.TestActivity;
import android.os.Bundle;
import android.view.View;

public class TlsTestActivity extends TestActivity {

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    setContentView(R.layout.tls_test_activity);

    findViewById(R.id.no_chain_of_trust_check).setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View v) {
        startTest(new NoSslCertificateChainOfTrustCheckTest());
      }
    });

    findViewById(R.id.no_hostname_verification).setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View v) {
        startTest(new NoSslCertificateHostnameVerificationTest());
      }
    });

    findViewById(R.id.tls_server_auth_not_required).setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View v) {
        startTest(new NoTlsServerAutenticationRequiredTest());
      }
    });
  }
}
