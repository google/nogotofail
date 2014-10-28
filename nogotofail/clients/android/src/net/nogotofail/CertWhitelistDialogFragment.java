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
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.content.DialogInterface;
import android.os.Bundle;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

/**
 * Dialog for whitelisting unknown certificates for the mitm server.
 */
public class CertWhitelistDialogFragment extends DialogFragment {

  /**
   * Callback listener for the dialog.
   */
  public interface CertWhitelistDialogListener {
    public void onCertWhitelist(X509Certificate cert);
    public void onCertBlacklist(X509Certificate cert);
    public void onCertUndecided(X509Certificate cert);
  }
  private CertWhitelistDialogListener mListener;

  static CertWhitelistDialogFragment newInstance(X509Certificate certificate) {
    CertWhitelistDialogFragment frag = new CertWhitelistDialogFragment();
    frag.setCancelable(true);

    Bundle args = new Bundle();
    args.putSerializable("certificate", certificate);
    frag.setArguments(args);
    return frag;
  }

  @Override
  public void onAttach(Activity activity) {
    super.onAttach(activity);
    mListener = (CertWhitelistDialogListener) activity;
  }

  @Override
  public Dialog onCreateDialog(Bundle savedInstanceState) {
    final X509Certificate certificate =
        (X509Certificate) getArguments().getSerializable("certificate");

    AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());
    CharSequence message = getString(R.string.whitelist_message, fingerprint(certificate));

    builder.setTitle(R.string.whitelist_title)
           .setMessage(message)
           .setPositiveButton(R.string.button_whitelist, new DialogInterface.OnClickListener() {
             @Override
             public void onClick(DialogInterface dialog, int id) {
               mListener.onCertWhitelist(certificate);
             }
           })
           .setNegativeButton(R.string.button_blacklist, new DialogInterface.OnClickListener() {
             @Override
             public void onClick(DialogInterface dialog, int id) {
               mListener.onCertBlacklist(certificate);
             }
           });
    return builder.create();
  }

  @Override
  public void onCancel(DialogInterface dialog) {
    super.onCancel(dialog);

    final X509Certificate certificate =
        (X509Certificate) getArguments().getSerializable("certificate");
    mListener.onCertUndecided(certificate);
  }

  private String fingerprint(X509Certificate certificate) {
    MessageDigest digester;
    byte[] x509EncodedKey;
    PublicKey key = certificate.getPublicKey();
    try {
      digester = MessageDigest.getInstance("SHA256");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Unable to get digest", e);
    }
    try {
      x509EncodedKey = KeyFactory.getInstance(key.getAlgorithm())
          .getKeySpec(key, X509EncodedKeySpec.class).getEncoded();
    } catch (GeneralSecurityException e) {
      throw new RuntimeException("Unable to encode key", e);
    }
    byte[] digest = digester.digest(x509EncodedKey);
    StringBuilder builder = new StringBuilder();
    for (int i = 0; i < digest.length; i++) {
      builder.append(String.format("%02X", digest[i]));
      if (i != digest.length - 1) {
        builder.append(":");
      }
    }
    return builder.toString();
  }
}
