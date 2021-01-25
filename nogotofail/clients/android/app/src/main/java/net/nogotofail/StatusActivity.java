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

import android.app.Activity;
import android.app.DialogFragment;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;

/**
 * {@link Activity} that displays the status of this app.
 */
public class StatusActivity extends Activity
    implements CertWhitelistDialogFragment.CertWhitelistDialogListener {

  private static final String FRAGMENT_TAG_WHITELIST_DIALOG = "Whitelist";

  private final Handler mHandler = new Handler();

  private TextView mStatusView;
  private View mReconnectButton;
  private RouterSocketClient mSocketClient;
  private SocketClientStateChangeListener mSocketClientStateChangeListener;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.status_activity);

    mStatusView = (TextView) findViewById(R.id.status);
    mReconnectButton = findViewById(R.id.reconnect);
    mReconnectButton.setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View v) {
        onReconnectButtonClicked();
      }
    });
    mSocketClient = ((NoGotoFailApplication) getApplication()).getRouterSocketClient();
    mSocketClientStateChangeListener = new SocketClientStateChangeListener();
  }

  @Override
  protected void onStart() {
    super.onStart();
    mSocketClient.addStateChangeListener(mSocketClientStateChangeListener);
  }

  @Override
  protected void onStop() {
    mSocketClient.removeStateChangeListener(mSocketClientStateChangeListener);
    super.onStop();
  }

  @Override
  public boolean onCreateOptionsMenu(Menu menu) {
      MenuInflater inflater = getMenuInflater();
      inflater.inflate(R.menu.status_activity_actions, menu);

      // Display the Send Feedback menu item only if Google Feedback is available
      menu.findItem(R.id.send_feedback).setVisible(
          FeedbackReporter.isGoogleFeedbackInstalled(this));

      return super.onCreateOptionsMenu(menu);
  }

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {
      switch (item.getItemId()) {
          case R.id.action_settings:
              onSettingsActionInvoked();
              return true;
          case R.id.send_feedback:
              FeedbackReporter.launchGoogleFeedback(this);
              return true;
          default:
              return super.onOptionsItemSelected(item);
      }
  }

  private void onSettingsActionInvoked() {
    startActivity(new Intent(this, SettingsActivity.class));
  }

  private void onReconnectButtonClicked() {
    mSocketClient.restart();
  }

  private void setStatus(final CharSequence status) {
    if (isFinishing()) {
      return;
    }
    mHandler.post(new Runnable() {
      @Override
      public void run() {
        mStatusView.setText(status);
      }
    });
  }

  @Override
  public void onCertWhitelist(X509Certificate certificate) {
    mSocketClient.whitelistCertificate(certificate);
    RouterSocketService.cancelUnknownCertNotification(this);
    mSocketClient.restart();
  }

  @Override
  public void onCertBlacklist(X509Certificate certificate) {
    mSocketClient.blacklistCertificate(certificate);
    RouterSocketService.cancelUnknownCertNotification(this);
    mSocketClient.restart();
  }

  @Override
  public void onCertUndecided(X509Certificate certificate) {
    RouterSocketService.cancelUnknownCertNotification(this);
  }

  private void showWhitelistDialog(final X509Certificate certificate) {
    if (isFinishing()) {
      return;
    }
    mHandler.post(new Runnable() {
      @Override
      public void run() {
        // Stop the socket client until the user makes a choice
        // Should be restarted after the dialog is completed
        mSocketClient.stop();

        DialogFragment dialog = CertWhitelistDialogFragment.newInstance(certificate);
        dialog.show(getFragmentManager(), FRAGMENT_TAG_WHITELIST_DIALOG);
      }
    });
  }

  private class SocketClientStateChangeListener implements RouterSocketClient.StateChangeListener {
    @Override
    public void onStarted() {
      setStatus("Started");
    }

    @Override
    public void onConnecting(InetSocketAddress address) {
      setStatus("Connecting to " + address);

      // Dismiss the cert whitelist dialog if it's displayed.
      mHandler.post(new Runnable() {
        @Override
        public void run() {
          DialogFragment whitelistDialog = (DialogFragment)
              getFragmentManager().findFragmentByTag(FRAGMENT_TAG_WHITELIST_DIALOG);
          if (whitelistDialog != null) {
            whitelistDialog.dismiss();
          }
        }
      });
    }

    @Override
    public void onConnected(InetSocketAddress address) {
      setStatus("Connected to " + address);
    }

    @Override
    public void onWaitingToRetry(String cause, long delayMillis) {
      setStatus("Waiting to retry (" + (delayMillis / 1000) + "s): " + cause);
    }

    @Override
    public void onStopped() {
      setStatus("Stopped");
    }

    @Override
    public void onUnknownCertificate(X509Certificate certificate) {
      setStatus("Unknown Certificate " + certificate);
      showWhitelistDialog(certificate);
    }
  }
}
