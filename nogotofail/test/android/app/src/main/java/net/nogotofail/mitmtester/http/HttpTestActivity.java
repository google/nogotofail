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

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import net.nogotofail.mitmtester.R;
import net.nogotofail.mitmtester.TestActivity;

public class HttpTestActivity extends TestActivity {

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    setContentView(R.layout.http_test_activity);

    final Context app_context = this.getApplicationContext();

    findViewById(R.id.http_with_authorization).setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View v) {
        startTest(new CleartextHttpCredentialsTest());
      }
    });

    findViewById(R.id.test_http_pii).setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View v) { startTest(new HttpPiiTest(app_context));
      }
    });

    findViewById(R.id.test_https_pii).setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View v) { startTest(new HttpsPiiTest(app_context)); }
    });
  }
}
