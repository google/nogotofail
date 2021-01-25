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
import android.content.Context;
import android.os.Build;
import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * Assorted utilities.
 */
public abstract class Utils {
  private Utils() {}

  public static byte[] readResource(Context context, int resId) throws IOException {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    InputStream in = null;
    byte[] buf = new byte[16 * 1024];
    try {
        in = context.getResources().openRawResource(resId);
        int chunkSize;
        while ((chunkSize = in.read(buf)) != -1) {
            result.write(buf, 0, chunkSize);
        }
        return result.toByteArray();
    } finally {
        Closeables.closeQuietly(in);
    }
  }

  /**
   * Finds the specified element in the provided array.
   *
   * @return smallest index at which the element is present in the array or {@code -1} if the
   *         element is not present in the array.
   */
  public static <T> int indexOf(T[] values, T value) {
    for (int i = 0; i < values.length; i++) {
      if (value == null) {
        if (values[i] == null) {
          return i;
        }
      } else {
        if (value.equals(values[i])) {
          return i;
        }
      }
    }
    return -1;
  }

  public static String keyToBase64(PublicKey key) {
    try {
      byte[] x509EncodedKey = KeyFactory.getInstance(key.getAlgorithm())
          .getKeySpec(key, X509EncodedKeySpec.class).getEncoded();
      return Base64.encodeToString(x509EncodedKey, Base64.NO_WRAP);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException("Unable to encode key", e);
    }

  }

  @SuppressWarnings("deprecation")
  @SuppressLint("NewApi")
  public static Notification buildNotification(Notification.Builder builder) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
      return builder.build();
    } else {
      return builder.getNotification();
    }
  }

  @SuppressLint("NewApi")
  public static void setNotificationPriorityMin(Notification.Builder builder) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
      builder.setPriority(Notification.PRIORITY_MIN);
    }
  }
}
