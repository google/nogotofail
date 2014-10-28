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

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.IBinder;
import android.util.Log;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;

/**
 * {@code Service} that maintains a TCP connection to the MiTM server if necessary.
 *
 * <p>The service starts whenever the app starts, when the state of data connectivity changes, or
 * after this app is updated. The service then ensures that the {@link RouterSocketClient} maintains
 * its connection to the server. Once the service stops, it shuts down the
 * {@code RouterSocketClient}.
 */
public class RouterSocketService extends Service {

  private static final String TAG = RouterSocketService.class.getSimpleName();
  private static final String ACTION_APP_STARTED =
      RouterSocketService.class.getName() + ".APP_STARTED";
  private static final int FOREGROUND_SERVICE_NOTIFICATION_ID = 173639;

  private ConnectivityManager mConnectivityManager;
  private RouterSocketClient mSocketClient;
  private RouterSocketClientStateChangeListener mSocketClientStateChangeListener;

  @Override
  public void onCreate() {
    Log.i(TAG, "onCreate");
    super.onCreate();

    mConnectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);

    mSocketClient = ((NoGotoFailApplication) getApplication()).getRouterSocketClient();
    mSocketClientStateChangeListener = new RouterSocketClientStateChangeListener();
    mSocketClient.addStateChangeListener(mSocketClientStateChangeListener);
    mSocketClient.onServiceStarted();

    // Turn this Service into a foreground service which is much less likely to be killed by the
    // framework in low resource conditions. Unfortunately, this means that a notification will be
    // displayed while the service is running. We set the priority of this notification to the
    // lowest value, making it less likely to be displayed.
    Notification.Builder notificationBuilder = new Notification.Builder(this)
        .setSmallIcon(R.drawable.ic_notify_default)
        .setContentTitle(getString(R.string.foreground_service_notification));
    Utils.setNotificationPriorityMin(notificationBuilder);
    startForeground(
        FOREGROUND_SERVICE_NOTIFICATION_ID, Utils.buildNotification(notificationBuilder));
  }

  @Override
  public void onDestroy() {
    Log.i(TAG, "onDestroy");
    if (mSocketClient != null) {
      mSocketClient.onServiceStopped();
      mSocketClient.removeStateChangeListener(mSocketClientStateChangeListener);
    }
    cancelUnknownCertNotification(this);
    stopForeground(true);

    super.onDestroy();
  }

  @Override
  public int onStartCommand(Intent intent, int flags, int startId) {
    Log.d(TAG, "onStartCommand(" + intent + ")");
    String action = (intent != null) ? intent.getAction() : null;
    if (ConnectivityManager.CONNECTIVITY_ACTION.equals(action)) {
      NetworkInfo networkInfo = mConnectivityManager.getActiveNetworkInfo();
      mSocketClient.onDataConnectivityMayHaveChanged(networkInfo);
    }
    return START_STICKY;
  }

  @Override
  public IBinder onBind(Intent intent) {
    return null;
  }

  public static void startService(Context context) {
    sendCommandToService(context, new Intent(ACTION_APP_STARTED));
  }

  private static void sendCommandToService(Context context, Intent intent) {
    Log.d(TAG, "sendCommandToService(): " + intent);
    intent.setComponent(new ComponentName(context, RouterSocketService.class));
    intent.setPackage(context.getPackageName());
    context.startService(intent);
  }

  /**
   * Receiver of broadcasts of interest to the {@link RouterSocketService}.
   */
  public static class BroadcastListener extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
      Log.d(TAG, "Received broadcast: " + intent);

      if (intent == null) {
        return;
      }
      String action = intent.getAction();
      if (action == null) {
        return;
      }

      if (ConnectivityManager.CONNECTIVITY_ACTION.equals(action)) {
        sendCommandToService(context, intent);
      } else if (action.equals(Intent.ACTION_MY_PACKAGE_REPLACED)) {
        sendCommandToService(context, intent);
      }
    }
  }

  public static void cancelUnknownCertNotification(Context context) {
    NotificationManager notificationManager =
        (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
    notificationManager.cancel(UNKNOWN_SERVER_CERT_NOTIFICATION_ID);
  }

  private static final int UNKNOWN_SERVER_CERT_NOTIFICATION_ID = 1727813;

  private class RouterSocketClientStateChangeListener
      implements RouterSocketClient.StateChangeListener {

    @Override
    public void onStarted() {}

    @Override
    public void onConnecting(InetSocketAddress address) {}

    @Override
    public void onConnected(InetSocketAddress address) {
      // Connection to server succeeded -- the certificate it presented must have been trusted.
      cancelUnknownCertNotification(RouterSocketService.this);
    }

    @Override
    public void onWaitingToRetry(String cause, long delayMillis) {}

    @Override
    public void onStopped() {}

    @Override
    public void onUnknownCertificate(X509Certificate certificate) {
      Context context = RouterSocketService.this;
      Notification.Builder notificationBuilder = new Notification.Builder(context)
          .setDefaults(Notification.DEFAULT_ALL)
          .setOnlyAlertOnce(true)
          .setSmallIcon(R.drawable.ic_notify_default)
          .setTicker(getString(R.string.whitelist_notification_ticker))
          .setContentTitle(getString(R.string.whitelist_notification_title))
          .setContentText(getString(R.string.whitelist_notification_text))
          .setContentIntent(PendingIntent.getActivity(
              context,
              0,
              CertWhitelistPromptActivity.getLaunchIntent(context, certificate)
                  .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
              PendingIntent.FLAG_UPDATE_CURRENT));

      NotificationManager notificationManager =
          (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
      notificationManager.notify(
          UNKNOWN_SERVER_CERT_NOTIFICATION_ID, Utils.buildNotification(notificationBuilder));
    }
  }
}
