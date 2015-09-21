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
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.Build;
import android.preference.PreferenceManager;
import android.util.Log;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;

/**
 * Handler of the "vulnerability notify" commands from the MiTM server.
 */
public class VulnNotifyCommandHandler implements RouterConnectionHandler.CommandHandler {
  private static final String TAG = VulnNotifyCommandHandler.class.getSimpleName();

  private final Context mContext;
  private final SharedPreferences mPreferences;

  public VulnNotifyCommandHandler(Context context) {
    mContext = context;
    mPreferences = PreferenceManager.getDefaultSharedPreferences(mContext);
  }

  @Override
  public String handleCommand(
      InetAddress localAddress, String parameters) throws IOException {
    // Request:
    //   <request id> <vuln type> <dst host/addr> <dst port> [<pkg name> <version code>[, ...]]]
    String[] tokens = parameters.split("\\s", 5);
    String requestId = tokens[0];
    String type = tokens[1];
    String dstAddressText = tokens[2];
    int dstPort = Integer.parseInt(tokens[3]);
    String[] packageNamesAndVersionCodes = tokens[4].split(",");
    // Whitespace is permitted after comma -- get rid of the whitespace
    for (int i = 0; i < packageNamesAndVersionCodes.length; i++) {
      packageNamesAndVersionCodes[i] = packageNamesAndVersionCodes[i].trim();
    }

    onVulnerabilityReported(requestId, type, dstAddressText, dstPort, packageNamesAndVersionCodes);
    return "OK";
  }

  private void onVulnerabilityReported(
      String requestId,
      String vulnerabilityType,
      String destinationAddress,
      int destinationPort,
      String[] packageNamesAndVersionCodes) {
    Log.w(TAG, "Vulnerability detected. Request ID: " + requestId
        + ", type: " + vulnerabilityType
        + ", destination: " + destinationAddress + ":" + destinationPort
        + ", packages: " + Arrays.asList(packageNamesAndVersionCodes));

    // Display a notification, if necessary
    String[] packageNames = new String[packageNamesAndVersionCodes.length];
    for (int i = 0; i < packageNamesAndVersionCodes.length; i++) {
      String packageNameAndVersionCode = packageNamesAndVersionCodes[i];
      String[] tokens = packageNameAndVersionCode.split("\\s+");
      packageNames[i] = tokens[0];
    }

    if (!NotificationsPreferenceFragment.isNotificationPermitted(
        mContext, vulnerabilityType, packageNames)) {
      // Notification muted
      return;
    }

    NotificationManager notificationManager =
        (NotificationManager) mContext.getSystemService(Context.NOTIFICATION_SERVICE);
    if (notificationManager == null) {
      Log.w(TAG, "NotificationManager not available. Skipping notification.");
      return;
    }

    String ringtoneUriString = mPreferences.getString(
        mContext.getString(R.string.vuln_notification_ringtone_pref_key), null);
    Uri ringtoneUri;
    if (ringtoneUriString == null) {
      // Default
      ringtoneUri =
          RingtoneManager.getActualDefaultRingtoneUri(mContext, RingtoneManager.TYPE_NOTIFICATION);
    } else if (ringtoneUriString.isEmpty()) {
      // Silent
      ringtoneUri = null;
    } else {
      ringtoneUri = Uri.parse(ringtoneUriString);
    }
    boolean vibrate = mPreferences.getBoolean(
        mContext.getString(R.string.vuln_notification_vibrate_pref_key),
        mContext.getResources().getBoolean(R.bool.vuln_notification_vibrate_pref_default_value));
    int notificationDefaults = Notification.DEFAULT_LIGHTS;
    if (vibrate) {
      notificationDefaults |= Notification.DEFAULT_VIBRATE;
    }

    PackageManager packageManager = mContext.getPackageManager();
    StringBuilder packageNamesText = new StringBuilder();
    for (String packageName : packageNames) {
      if (packageNamesText.length() > 0) {
        packageNamesText.append(", ");
      }
      PackageInfo packageInfo;
      try {
        packageInfo = packageManager.getPackageInfo(packageName, 0);
      } catch (NameNotFoundException e) {
        packageNamesText.append(packageName);
        continue;
      }
      ApplicationInfo applicationInfo = packageInfo.applicationInfo;
      if (applicationInfo == null) {
        packageNamesText.append(packageName);
        continue;
      }
      CharSequence applicationLabel = packageManager.getApplicationLabel(applicationInfo);
      if (applicationLabel == null) {
        packageNamesText.append(packageName);
        continue;
      }
      packageNamesText.append(applicationLabel);
    }

    String packageList = packageNamesText.toString();
    String destination = destinationAddress + ":" + destinationPort;
    String vulnerabilityDetails = getVulnerabilityDetails(vulnerabilityType);
    CharSequence contentText = mContext.getString(
        R.string.vuln_detected_notification_text,
        packageList,
        destination,
        vulnerabilityDetails);
    Notification.Builder notificationBuilder = new Notification.Builder(mContext)
        .setDefaults(notificationDefaults)
        .setOnlyAlertOnce(true)
        .setAutoCancel(true)
        .setSound(ringtoneUri)
        .setSmallIcon(R.drawable.ic_notify_vuln)
        .setContentTitle(mContext.getString(R.string.vuln_detected_notification_title))
        .setContentText(contentText)
        .setTicker(mContext.getResources().getString(
            R.string.vuln_detected_notification_ticker,
            packageList,
            destination,
            vulnerabilityDetails));

    // Any previous notifications with the same tag will be replaced by this notification
    List<String> packageNamesList = Arrays.asList(packageNames);
    String notificationTag = vulnerabilityType + " " + packageNamesList;

    // Show the content text in full on platforms that support it.
    // Add a Mute action on platforms that support it.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
      setNotificationBigTextStyle(notificationBuilder, contentText);
      addNotificationAction(
          notificationBuilder,
          0,
          mContext.getString(R.string.vuln_detected_notification_action_mute),
          PendingIntent.getBroadcast(
              mContext,
              0,
              MuteNotificationsReceiver.getLaunchIntent(
                  mContext,
                  vulnerabilityType,
                  packageNamesList,
                  notificationTag),
              PendingIntent.FLAG_UPDATE_CURRENT));
    }
    Notification notification = Utils.buildNotification(notificationBuilder);
    notificationManager.notify(notificationTag, 0, notification);
  }

  private String getVulnerabilityDetails(String vulnerabilityType) {
    int resId = mContext.getResources().getIdentifier(
        "vuln_" + vulnerabilityType, "string", mContext.getPackageName());
    if (resId == 0) {
      return vulnerabilityType;
    }
    return mContext.getString(resId);
  }

  @SuppressLint("NewApi")
  private static void setNotificationBigTextStyle(Notification.Builder builder, CharSequence text) {
    builder.setStyle(new Notification.BigTextStyle().bigText(text));
  }

  @SuppressLint("NewApi")
  private static void addNotificationAction(
      Notification.Builder builder,
      int icon,
      CharSequence title,
      PendingIntent intent) {
    builder.addAction(icon, title, intent);
  }
}
