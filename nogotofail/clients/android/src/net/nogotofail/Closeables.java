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

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.Socket;

/**
 * Utility methods for working with {@link Closeable} objects.
 */
public final class Closeables {

  private Closeables() {}

  /**
   * Closes the provided {@link Socket} and consumes the {@link IOException} that this operation
   * may throw. Does nothing if the {@code Socket} is {@code null}.
   *
   * <p>This method is specially designed for {@code Socket} instances because on older Android
   * platforms {@code Socket} does not implement {@link Closeable}.
   */
  public static void closeQuietly(Socket socket) {
    if (socket == null) {
      return;
    }
    try {
      socket.close();
    } catch (IOException ignored) {}
  }

  /**
   * Closes the provided {@link Reader} and consumes the {@link IOException} that this
   * operation may throw. Does nothing if the {@code Socket} is {@code null}.
   *
   * <p>This method is specially designed for {@code Reader} instances because on older Android
   * platforms {@code Socket} does not implement {@link Closeable}.
   */
  public static void closeQuietly(Reader in) {
    if (in == null) {
      return;
    }
    try {
      in.close();
    } catch (IOException ignored) {}
  }

  /**
   * Closes the provided {@link InputStream} and consumes the {@link IOException} that this
   * operation may throw. Does nothing if the {@code Socket} is {@code null}.
   *
   * <p>This method is specially designed for {@code InputStream} instances because on older Android
   * platforms {@code Socket} does not implement {@link Closeable}.
   */
  public static void closeQuietly(InputStream in) {
    if (in == null) {
      return;
    }
    try {
      in.close();
    } catch (IOException ignored) {}
  }
}
