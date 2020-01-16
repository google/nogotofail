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

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceFragment;
import android.preference.PreferenceManager;
import android.text.TextUtils;
import android.widget.Toast;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * {@link PreferenceFragment} with advanced/miscellaneous preferences.
 */
public class AdvancedPreferenceFragment extends PreferenceFragment {

  private static final Object sInstallationIdLock = new Object();

  private static final int MIN_TCP_PORT_NUMBER = 1;
  private static final int MAX_TCP_PORT_NUMBER = 65535;

  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    addPreferencesFromResource(R.xml.advanced_settings);

    Preference mitmServerHost = findPreference(getString(R.string.mitm_server_host_pref_key));
    mitmServerHost.setSummary(getMitmServerHost(getActivity()));
    mitmServerHost.setOnPreferenceChangeListener(new Preference.OnPreferenceChangeListener() {
      @Override
      public boolean onPreferenceChange(Preference preference, Object newValue) {
        String host = (String) newValue;
        preference.setSummary(getMitmServerHost(preference.getContext(), host));
        return true;
      }
    });

    Preference mitmServerPort = findPreference(getString(R.string.mitm_server_port_pref_key));
    mitmServerPort.setSummary(String.valueOf(getMitmServerPort(getActivity())));
    mitmServerPort.setOnPreferenceChangeListener(new Preference.OnPreferenceChangeListener() {
      @Override
      public boolean onPreferenceChange(Preference preference, Object newValue) {
        String portString = (String) newValue;
        if (portString != null) {
          portString = portString.trim();
        }
        if (!TextUtils.isEmpty(portString)) {
          // Port is not empty -- alert the user if the port invalid.
          int port = -1;
          try {
            port = Integer.parseInt(portString);
          } catch (NumberFormatException ignored) {}
          if ((port < MIN_TCP_PORT_NUMBER) || (port > MAX_TCP_PORT_NUMBER)) {
            new AlertDialog.Builder(preference.getContext())
                .setMessage(R.string.mitm_server_port_invalid_alert)
                .setPositiveButton(android.R.string.ok, null)
                .show();
            return false;
          }
        }

        preference.setSummary(
            String.valueOf(getMitmServerPort(preference.getContext(), portString)));
        return true;
      }
    });

    Preference revokeMitmServerAuth =
        findPreference(getString(R.string.mitm_server_revoke_auth_pref_key));
    revokeMitmServerAuth.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
      @Override
      public boolean onPreferenceClick(final Preference preference) {
        new AlertDialog.Builder(preference.getContext())
            .setMessage(R.string.mitm_server_revoke_auth_prompt_message)
            .setPositiveButton(
                R.string.mitm_server_revoke_auth_prompt_positive_action,
                new DialogInterface.OnClickListener() {
                  @Override
                  public void onClick(DialogInterface dialog, int which) {
                    new PreferencesBackedPinningX509TrustManager(preference.getContext()).clear();
                    getRouterSocketClient().restart();
                  }
                })
            .setNegativeButton(android.R.string.cancel, null)
            .show();
        return true;
      }
    });

    final Preference displayInstallationIdPreference =
        findPreference(getString(R.string.install_id_display_pref_key));
    displayInstallationIdPreference.setSummary(getInstallationId(getActivity()));
    displayInstallationIdPreference.setOnPreferenceClickListener(
        new Preference.OnPreferenceClickListener() {
      @Override
      public boolean onPreferenceClick(Preference preference) {
        ClipboardManager clipboardManager =
            (ClipboardManager) getActivity().getSystemService(Context.CLIPBOARD_SERVICE);
        clipboardManager.setPrimaryClip(ClipData.newPlainText(
            "nogotofail installation ID",
            getInstallationId(getActivity())));
        Toast.makeText(
            getActivity(),
            getString(R.string.install_id_copied_to_clipboard_toast),
            Toast.LENGTH_SHORT).show();
        return true;
      }
    });

    Preference resetInstallationIdPreference =
        findPreference(getString(R.string.install_id_reset_pref_key));
    resetInstallationIdPreference.setOnPreferenceClickListener(
        new Preference.OnPreferenceClickListener() {
      @Override
      public boolean onPreferenceClick(Preference preference) {
        resetInstallationId(getActivity());
        displayInstallationIdPreference.setSummary(getInstallationId(getActivity()));
        getRouterSocketClient().restart();
        return true;
      }
    });
  }

  public static String getMitmServerHost(Context context) {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
    String prefKey = context.getString(R.string.mitm_server_host_pref_key);
    String prefValue = preferences.getString(prefKey, null);
    return getMitmServerHost(context, prefValue);
  }

  private static String getMitmServerHost(Context context, String prefValue) {
    if (prefValue != null) {
      prefValue = prefValue.trim();
    }
    if (!TextUtils.isEmpty(prefValue)) {
      return prefValue;
    }
    // null or empty -- use default
    return context.getString(R.string.mitm_server_host_pref_default_value);
  }

  public static int getMitmServerPort(Context context) {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
    String prefKey = context.getString(R.string.mitm_server_port_pref_key);
    String prefValue = preferences.getString(prefKey, null);
    return getMitmServerPort(context, prefValue);
  }

  private static int getMitmServerPort(Context context, String prefValue) {
    if (prefValue != null) {
      prefValue = prefValue.trim();
    }
    if (!TextUtils.isEmpty(prefValue)) {
      try {
        int port = Integer.parseInt(prefValue);
        if ((port >= MIN_TCP_PORT_NUMBER) && (port <= MAX_TCP_PORT_NUMBER)) {
          return port;
        }
      } catch (NumberFormatException ignored) {}
    }
    // null, empty, doesn't parse, or out of range -- use default.
    return Integer.parseInt(context.getString(R.string.mitm_server_port_pref_default_value));
  }

  public static String getInstallationId(Context context) {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
    String prefKey = context.getString(R.string.install_id_pref_key);
    String installationId;
    synchronized (sInstallationIdLock) {
      installationId = preferences.getString(prefKey, null);
      if (installationId == null) {
        installationId = generateInstallationId();
        preferences.edit().putString(prefKey, installationId).apply();
      }
    }
    return installationId;
  }

  private static void resetInstallationId(Context context) {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
    String prefKey = context.getString(R.string.install_id_pref_key);
    synchronized (sInstallationIdLock) {
      preferences.edit().putString(prefKey, generateInstallationId()).apply();
    }
  }

  private static final Set<String> PREF_KEYS_NEEDING_RECONNECT = new HashSet<String>();

  public static boolean isReconnectRequiredToApplyPreference(Context context, String key) {
    if (key == null) {
      return false;
    }
    synchronized (PREF_KEYS_NEEDING_RECONNECT) {
      if (PREF_KEYS_NEEDING_RECONNECT.isEmpty()) {
        PREF_KEYS_NEEDING_RECONNECT.add(context.getString(R.string.mitm_server_host_pref_key));
        PREF_KEYS_NEEDING_RECONNECT.add(context.getString(R.string.mitm_server_port_pref_key));
        PREF_KEYS_NEEDING_RECONNECT.add(context.getString(R.string.install_id_pref_key));
      }
      return PREF_KEYS_NEEDING_RECONNECT.contains(key);
    }
  }

  private static String generateInstallationId() {
    return UUID.randomUUID().toString();
  }

  private RouterSocketClient getRouterSocketClient() {
    return ((NoGotoFailApplication) getActivity().getApplication()).getRouterSocketClient();
  }
}
