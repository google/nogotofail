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

import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.text.TextUtils;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

/**
 * {@link BroadcastReceiver} which adjusts preferences to mute notifications about vulnerabilities
 * for packages listed in the received {@code Intents}.
 */
public class MuteNotificationsReceiver extends BroadcastReceiver {

  private static final String EXTRA_NOTIFICATION_TAG = MuteNotificationsReceiver.class.getName()
      + ".notification_tag";

  @Override
  public void onReceive(Context context, Intent intent) {
    if (intent == null) {
      return;
    }
    Uri data = intent.getData();
    if (data == null) {
      return;
    }
    if (!"mute_notifications".equals(data.getScheme())) {
      throw new RuntimeException("Unexpected mute notifications URI: " + data);
    }
    String vulnerabilityType;
    String[] values = data.getSchemeSpecificPart().split(",");
    if (values.length < 1) {
      throw new RuntimeException("Unexpected mute notifications URI: " + data);
    }
    vulnerabilityType = values[0];
    List<String> packageNames = new ArrayList<String>(values.length - 1);
    for (int i = 1; i < values.length; i++) {
      packageNames.add(values[1]);
    }
    NotificationsPreferenceFragment.muteNotificationForPackages(
        context, vulnerabilityType, packageNames);

    String notificationTag = intent.getStringExtra(EXTRA_NOTIFICATION_TAG);
    if (notificationTag != null) {
      // For some reason the Notification does not get auto-dismissed when clicked, despite
      // FLAG_AUTO_CANCEL being set on it. Thus, we cancel the notification explicitly here...
      NotificationManager notificationManager =
          (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
      notificationManager.cancel(notificationTag, 0);
    }
    Toast.makeText(
        context.getApplicationContext(),
        R.string.vuln_detected_notification_action_mute_toast,
        Toast.LENGTH_LONG).show();
  }

  public static Intent getLaunchIntent(
      Context context,
      String vulnerabilityType,
      List<String> packageNames,
      String notificationTag) {
    Uri data = new Uri.Builder()
        .scheme("mute_notifications")
        .opaquePart(vulnerabilityType + "," + TextUtils.join(",", packageNames))
        .build();
    Intent intent = new Intent(context, MuteNotificationsReceiver.class)
        .setData(data);
    if (notificationTag != null) {
      intent.putExtra(EXTRA_NOTIFICATION_TAG, notificationTag);
    }
    return intent;
  }
}
