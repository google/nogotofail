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

package net.nogotofail;

import android.annotation.SuppressLint;
import android.app.Application;
import android.content.Context;
import android.net.ConnectivityManager;
import java.security.SecureRandom;

/**
 * {@link Application} object which initializes the various components of the app whenever the app's
 * process is created. It also serves as a container for app-level singleton instances.
 */
public class NoGotoFailApplication extends Application {

  private RouterSocketClient mRouterSocketClient;

  /**
   * Gets the one and only instance of the MiTM server socket client.
   */
  @SuppressLint("TrulyRandom") // SecureRandom only used for non-cryptographic operation
  synchronized RouterSocketClient getRouterSocketClient() {
    if (mRouterSocketClient == null) {
      ConnectivityManager connectivityManager =
          (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
      mRouterSocketClient = new RouterSocketClient(
          this,
          connectivityManager,
          new RouterConnectionHandler(this),
          new SecureRandom());
    }
    return mRouterSocketClient;
  }

  @Override
  public void onCreate() {
    super.onCreate();

    RouterSocketService.startService(this);
  }

  @Override
  public void onTerminate() {
    if (mRouterSocketClient != null) {
      mRouterSocketClient.close();
    }
    mRouterSocketClient = null;

    super.onTerminate();
  }
}
