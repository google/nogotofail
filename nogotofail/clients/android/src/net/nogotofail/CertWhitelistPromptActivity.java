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
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * {@code Activity} which tells the user that the MiTM server is untrusted and prompts whether to
 * trust it going forward.
 */
public class CertWhitelistPromptActivity extends Activity
    implements CertWhitelistDialogFragment.CertWhitelistDialogListener {

  private static final String EXTRA_DER_ENCODED_X509_CERTIFICATE =
      CertWhitelistPromptActivity.class.getName() + ".certificate";

  private RouterSocketClient mSocketClient;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    mSocketClient = ((NoGotoFailApplication) getApplication()).getRouterSocketClient();

    Intent intent = getIntent();
    byte[] encodedCert = intent.getByteArrayExtra(EXTRA_DER_ENCODED_X509_CERTIFICATE);
    if (encodedCert == null) {
      throw new RuntimeException("No certificate provided");
    }
    X509Certificate certificate;
    try {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      certificate =
          (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(encodedCert));
    } catch (CertificateException e) {
      throw new RuntimeException("Failed to decode certificate", e);
    }

    CertWhitelistDialogFragment dialogFragment =
        CertWhitelistDialogFragment.newInstance(certificate);
    dialogFragment.show(getFragmentManager(), "whitelist");
  }

  @Override
  public void onCertWhitelist(X509Certificate certificate) {
    mSocketClient.whitelistCertificate(certificate);
    RouterSocketService.cancelUnknownCertNotification(this);
    mSocketClient.restart();
    finish();
  }

  @Override
  public void onCertBlacklist(X509Certificate certificate) {
    mSocketClient.blacklistCertificate(certificate);
    RouterSocketService.cancelUnknownCertNotification(this);
    mSocketClient.restart();
    finish();
  }

  @Override
  public void onCertUndecided(X509Certificate certificate) {
    RouterSocketService.cancelUnknownCertNotification(this);
    finish();
  }

  public static Intent getLaunchIntent(Context context, X509Certificate certificate) {
    byte[] encodedCert;
    try {
      encodedCert = certificate.getEncoded();
    } catch (CertificateEncodingException e) {
      throw new RuntimeException("Failed to encode certificate", e);
    }

    return new Intent(context, CertWhitelistPromptActivity.class)
        .putExtra(EXTRA_DER_ENCODED_X509_CERTIFICATE, encodedCert);
  }
}
