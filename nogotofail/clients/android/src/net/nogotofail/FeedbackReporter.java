/*
 * Copyright 2011 Google Inc. All Rights Reserved.
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

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Bitmap;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;
import android.view.View;

import java.util.List;

/**
 * Sends bug reports using Google Feedback.
 */
public class FeedbackReporter {

  private static final String LOG_TAG = FeedbackReporter.class.getName();

  private static final Intent BUG_REPORT_INTENT = new Intent("android.intent.action.BUG_REPORT");

  private static final int MAX_SCREENSHOT_BYTES = 1024 * 1024;

  private FeedbackReporter() {
  }

  public static boolean isGoogleFeedbackInstalled(Context context) {
    return isSupportingServiceInstalled(context, BUG_REPORT_INTENT);
  }

  public static void launchGoogleFeedback(final Activity activity) {
    final ServiceConnection conn = new ServiceConnection() {
      @Override
      public void onServiceConnected(ComponentName name, IBinder service) {
        try {
          Parcel parcel = Parcel.obtain();
          try {
            Bitmap screenshot = getCurrentScreenshot(activity);
            if (screenshot != null) {
              screenshot.writeToParcel(parcel, 0);
            }
            service.transact(Binder.FIRST_CALL_TRANSACTION, parcel, null, 0);
          } finally {
            parcel.recycle();
          }
        } catch (RemoteException e) {
          Log.e(LOG_TAG, "Error connecting to bug report service", e);
        } finally {
          // The try-catch below is to avoid crashing when the unbind operation fails. Occasionally
          // the operation throws an IllegalArgumentException because the connection has been closed
          // by the OS/framework.
          try {
            activity.unbindService(this);
          } catch (Exception e) {
            Log.w(LOG_TAG, "Failed to unbind from bug report service", e);
          }
        }
      }

      @Override
      public void onServiceDisconnected(ComponentName name) {
      }
    };
    // Bind to the service after creating it if necessary
    boolean bound = activity.bindService(BUG_REPORT_INTENT, conn, Context.BIND_AUTO_CREATE);
    if (!bound) {
      Log.w(LOG_TAG, "Failed to bind to bug report service");
      return;
    }
  }

  private static Bitmap getCurrentScreenshot(Activity activity) {
    try {
      View currentView = activity.getWindow().getDecorView().getRootView();
      boolean drawingCacheWasEnabled = currentView.isDrawingCacheEnabled();
      currentView.setDrawingCacheEnabled(true);
      Bitmap bitmap = currentView.getDrawingCache();
      if (bitmap != null) {
        bitmap = resizeBitmap(bitmap);
      }
      if (!drawingCacheWasEnabled) {
        currentView.setDrawingCacheEnabled(false);
        currentView.destroyDrawingCache();
      }
      return bitmap;
    } catch (Exception e) {
      return null;
    }
  }

  private static Bitmap resizeBitmap(Bitmap bitmap) {
    // First convert to 16 bits per pixel
    bitmap = bitmap.copy(Bitmap.Config.RGB_565, false);
    // Then find a size that will consume less than MAX_SCREENSHOT_BYTES
    int width = bitmap.getWidth();
    int height = bitmap.getHeight();
    while (width * height * 2 > MAX_SCREENSHOT_BYTES) {
      width /= 2;
      height /= 2;
    }
    if (width != bitmap.getWidth()) {
      bitmap = Bitmap.createScaledBitmap(bitmap, width, height, true);
    }
    return bitmap;
  }

  /**
   * Returns true if an installed apk has a service that can handle the specified intent.
   */
  private static boolean isSupportingServiceInstalled(Context context, Intent intent) {
    PackageManager manager = context.getPackageManager();
    List<ResolveInfo> list = manager.queryIntentServices(intent, PackageManager.MATCH_DEFAULT_ONLY);
    return !list.isEmpty();
  }

}
