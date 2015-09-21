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

import android.content.Context;
import android.content.SharedPreferences;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;


/**
 * {@link X509TrustManager} that supports whitelisting and blacklisting certificates with the
 * state backed by {@link SharedPreferences}.
 * If an unknown certificate is detected a UnknownCertificateException will be raised to
 * disambiguate unknown certificate from a blacklisted certificate.
 */
public class PreferencesBackedPinningX509TrustManager implements X509TrustManager {

  private static final String PREFS_NAME = "whitelist";
  private static final int CERT_UNKNOWN = 0;
  private static final int CERT_WHITELISTED = 1;
  private static final int CERT_BLACKLISTED = 2;

  private final SharedPreferences mPrefs;

  public PreferencesBackedPinningX509TrustManager(Context context) {
    mPrefs = context.getSharedPreferences(PREFS_NAME, 0);
  }

  private void checkTrusted(X509Certificate[] chain, @SuppressWarnings("unused") String authType)
      throws CertificateException {
    if ((chain == null) || (chain.length == 0)) {
      throw new IllegalArgumentException("Empty certificate chain");
    }
    if (chain.length != 1) {
      throw new CertificateException("Only single-certificate chains supported. Length: "
          + chain.length);
    }
    X509Certificate cert = chain[0];
    // Check the SharedPrefs for an entry
    String encodedStr = Utils.keyToBase64(cert.getPublicKey());
    int status = mPrefs.getInt(encodedStr, CERT_UNKNOWN);

    if (status == CERT_BLACKLISTED) {
      throw new CertificateException("Blacklisted certificate");
    }
    if (status != CERT_WHITELISTED) {
      throw new UnknownCertificateException("Unknown remote certificate", cert);
    }
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    checkTrusted(chain, authType);
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    checkTrusted(chain, authType);
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return new X509Certificate[0];
  }

  public void whitelist(PublicKey key) {
    storeKeyStatus(key, CERT_WHITELISTED);
  }
  public void blacklist(PublicKey key) {
    storeKeyStatus(key, CERT_BLACKLISTED);
  }

  private void storeKeyStatus(PublicKey key, int status) {
    mPrefs.edit()
        .putInt(Utils.keyToBase64(key), status)
        .apply();
  }

  public void clear() {
    mPrefs.edit()
        .clear()
        .apply();
  }

  /**
   * {@link CertificateException} for unknown certificates (not whitelist or blackedlisted).
   * Contains the certificate that was presented.
   */
  public class UnknownCertificateException extends CertificateException {
    public final X509Certificate certificate;
    public UnknownCertificateException(String message, X509Certificate certificate) {
      super(message);
      this.certificate = certificate;
    }
  }
}
