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

package net.nogotofail.mitmtester;

import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * Base class for tests that are run in a background thread.
 */
public abstract class BackgroundTest {
  interface Listener {
    void onTestProgressChanged(CharSequence message);
    void onTestFailed(CharSequence reason);
    void onTestDone(String result);
  }

  private final Object mLock = new Object();
  private boolean mDone;
  private String mResult;
  private Thread mThread;
  private Listener mListener;

  protected BackgroundTest() {}

  public void setListener(Listener listener) {
    mListener = listener;
  }

  public final void start() {
    final Thread bgThread = new Thread(new Runnable() {
      @Override
      public void run() {
        try {
          runTest();
        } catch (Exception e) {
          StringWriter buf = new StringWriter();
          e.printStackTrace(new PrintWriter(buf));
          setTestFailed(buf.toString());
        } finally {
          boolean wasDone;
          String result;
          synchronized (mLock) {
            wasDone = setDone();
            result = mResult;
          }
          if (!wasDone) {
            Listener listener = mListener;
            if (listener != null) {
              listener.onTestDone(result);
            }
          }
        }
      }
    });

    synchronized (mLock) {
      mThread = bgThread;
    }
    bgThread.start();
  }

  public final void cancel() {
    Thread thread;
    synchronized (mLock) {
      boolean wasDone = setDone();
      if (wasDone) {
        return;
      }
      thread = mThread;
    }
    if (thread != null) {
      thread.interrupt();
    }
  }

  protected abstract void runTest() throws Exception;

  protected final boolean isDone() {
    synchronized (mLock) {
      return mDone;
    }
  }

  private boolean setDone() {
    synchronized (mLock) {
      boolean wasDone = mDone;
      mDone = true;
      return wasDone;
    }
  }

  protected final void setTestResult(String result) {
    synchronized (mLock) {
      mResult = result;
    }
  }

  protected final void setTestFailed(String reason) {
    boolean wasDone = setDone();
    if (wasDone) {
      return;
    }
    Listener listener = mListener;
    if (listener != null) {
      listener.onTestFailed(reason);
      listener.onTestDone(null);
    }
  }

  protected final void setProgressMessage(String message) {
    if (isDone()) {
      return;
    }
    Listener listener = mListener;
    if (listener != null) {
      listener.onTestProgressChanged(message);
    }
  }
}
