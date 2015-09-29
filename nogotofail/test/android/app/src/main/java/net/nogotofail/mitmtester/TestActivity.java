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

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.os.Handler;

/**
 * Base {@link Activity} for running tests.
 */
public abstract class TestActivity extends Activity {
  private BackgroundTestListener mBackgroundTestListener;

  protected final void startTest(BackgroundTest test) {
    BackgroundTestListener listener = new BackgroundTestListener(test);
    mBackgroundTestListener = listener;
    test.setListener(listener);
    test.start();
  }

  private class BackgroundTestListener implements BackgroundTest.Listener {

    private final Handler mHandler;
    private final BackgroundTest mTest;
    private ProgressDialog mProgressDialog;

    private BackgroundTestListener(BackgroundTest test) {
      mTest = test;
      mHandler = new Handler();
    }

    @Override
    public void onTestProgressChanged(final CharSequence message) {
      mHandler.post(new Runnable() {
        @Override
        public void run() {
          if (isFinishing()) {
            return;
          }
          if (mBackgroundTestListener != BackgroundTestListener.this) {
            return;
          }

          if (mProgressDialog == null) {
            mProgressDialog = ProgressDialog.show(TestActivity.this, null, message, true, true);
            mProgressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
              @Override
              public void onCancel(DialogInterface dialog) {
                mTest.cancel();
              }
            });
            mProgressDialog.setOnDismissListener(new DialogInterface.OnDismissListener() {
              @Override
              public void onDismiss(DialogInterface dialog) {
                mTest.cancel();
              }
            });
          } else {
            mProgressDialog.setMessage(message);
          }
        }
      });
    }

    @Override
    public void onTestFailed(final CharSequence reason) {
      mHandler.post(new Runnable() {
        @Override
        public void run() {
          if (isFinishing()) {
            return;
          }
          if (mBackgroundTestListener != BackgroundTestListener.this) {
            return;
          }

          new AlertDialog.Builder(TestActivity.this)
              .setIcon(android.R.drawable.ic_dialog_alert)
              .setTitle("Test failed")
              .setMessage(reason)
              .setPositiveButton(android.R.string.ok, null)
              .create()
              .show();
        }
      });
    }

    @Override
    public void onTestDone(final String result) {
      mHandler.post(new Runnable() {
        @Override
        public void run() {
          if (isFinishing()) {
            return;
          }

          if (mProgressDialog != null) {
            mProgressDialog.dismiss();
            mProgressDialog = null;
          }

          if (mBackgroundTestListener == BackgroundTestListener.this) {
            mBackgroundTestListener = null;
          }

          if (result != null) {
            new AlertDialog.Builder(TestActivity.this)
                .setIcon(android.R.drawable.ic_dialog_info)
                .setTitle("Test result")
                .setMessage(result)
                .setPositiveButton(android.R.string.ok, null)
                .create()
                .show();
          }
        }
      });
    }
  }
}
