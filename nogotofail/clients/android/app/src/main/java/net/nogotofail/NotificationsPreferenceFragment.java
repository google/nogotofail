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
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.media.Ringtone;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceCategory;
import android.preference.PreferenceFragment;
import android.preference.PreferenceManager;
import android.preference.RingtonePreference;

import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * {@link PreferenceFragment} with preferences about notifications.
 */
public class NotificationsPreferenceFragment extends PreferenceFragment {

  PreferenceCategory mMutedAppsPreferenceCategory;

  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    addPreferencesFromResource(R.xml.notifications_settings);

    RingtonePreference vulnRingtonePreference = (RingtonePreference)
        findPreference(getString(R.string.vuln_notification_ringtone_pref_key));
    final Uri defaultRingtoneUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);
    vulnRingtonePreference.setOnPreferenceChangeListener(
        new Preference.OnPreferenceChangeListener() {
      @Override
      public boolean onPreferenceChange(Preference preference, Object newValue) {
        setRingtonePreferenceSummary(
            (RingtonePreference) preference,
            (String) newValue,
            defaultRingtoneUri,
            getActivity());
        return true;
      }
    });

    setRingtonePreferenceSummary(
        vulnRingtonePreference,
        vulnRingtonePreference.getSharedPreferences().getString(
            vulnRingtonePreference.getKey(), null),
            defaultRingtoneUri,
        getActivity());

    mMutedAppsPreferenceCategory = (PreferenceCategory)
        findPreference(getString(R.string.vuln_notification_muted_apps_pref_category_key));

    populateMutedAppsList();
  }

  private void setRingtonePreferenceSummary(
      RingtonePreference preference, String value, Uri defaultValue, Context context) {
    if ((value != null) && (value.isEmpty())) {
      // Silent
      preference.setSummary(R.string.notification_ringtone_silent);
    } else {
      // Not silent
      Uri ringtoneUri;
      if (value == null) {
        ringtoneUri = defaultValue;
      } else {
        ringtoneUri = Uri.parse(value);
      }
      Ringtone ringtone = RingtoneManager.getRingtone(context, ringtoneUri);
      String ringtoneName = (ringtone != null) ? ringtone.getTitle(context) : null;
      preference.setSummary(ringtoneName);
    }
  }

  private void populateMutedAppsList() {
    final SharedPreferences mutePreferences =
        getMutePreferences(mMutedAppsPreferenceCategory.getContext());
    Set<String> packageNames = mutePreferences.getAll().keySet();
    if (!packageNames.isEmpty()) {
      final PackageManager packageManager = getActivity().getPackageManager();
      PackageEntryModel[] packageEntries = new PackageEntryModel[packageNames.size()];
      int nextPackageEntryIndex = 0;
      for (String packageName : packageNames) {
        String label;
        Drawable icon;
        try {
          ApplicationInfo applicationInfo = packageManager.getApplicationInfo(packageName, 0);
          icon = packageManager.getApplicationIcon(packageName);
          CharSequence labelCharSequence = packageManager.getApplicationLabel(applicationInfo);
          label = (labelCharSequence != null) ? String.valueOf(labelCharSequence) : packageName;
        } catch (PackageManager.NameNotFoundException e) {
          label = packageName;
          icon = null;
        }
        packageEntries[nextPackageEntryIndex++] = new PackageEntryModel(packageName, label, icon);
      }
      Arrays.sort(packageEntries, new PackageEntryModelByLabelComparator());
      for (final PackageEntryModel entry : packageEntries) {
        Preference preference = new Preference(mMutedAppsPreferenceCategory.getContext());
        preference.setPersistent(false);
        if (entry.icon != null) {
          preference.setIcon(entry.icon);
        }
        preference.setTitle(entry.label);
        mMutedAppsPreferenceCategory.addPreference(preference);
        preference.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
          @Override
          public boolean onPreferenceClick(final Preference preference) {
            showMutedVulnsForPackageDialog(entry.packageName, preference);
            return true;
          }
        });
      }
    }
  }

  private static void setMutedNotificationsForPackage(
      Context context, String packageName, Set<String> vulnerabilityTypes) {
    SharedPreferences mutePreferences = getMutePreferences(context);
    if (vulnerabilityTypes.isEmpty()) {
      mutePreferences.edit().remove(packageName).apply();
    } else {
      mutePreferences.edit().putStringSet(packageName, vulnerabilityTypes).apply();
    }
  }

  private static Set<String> getMutedNotificationsForPackage(Context context, String packageName) {
    SharedPreferences mutePreferences = getMutePreferences(context);
    return mutePreferences.getStringSet(packageName, Collections.<String>emptySet());
  }

  public static void muteNotificationForPackages(
      Context context,
      String vulnerabilityType,
      List<String> packageNames) {
    if (packageNames.isEmpty()) {
      return;
    }
    SharedPreferences mutePreferences = getMutePreferences(context);
    SharedPreferences.Editor mutePreferencesEditor = mutePreferences.edit();
    for (String packageName : packageNames) {
      Set<String> mutedVulnerabilityTypes = new HashSet<String>(
          mutePreferences.getStringSet(packageName, Collections.<String>emptySet()));
      if (mutedVulnerabilityTypes.add(vulnerabilityType)) {
        mutePreferencesEditor.putStringSet(packageName, mutedVulnerabilityTypes);
      }
    }
    mutePreferencesEditor.apply();
  }

  public static boolean isNotificationPermitted(
      Context context,
      String vulnerabilityType,
      String... packageNames) {
    SharedPreferences mainPreferences = PreferenceManager.getDefaultSharedPreferences(context);
    if (!mainPreferences.getBoolean(
        context.getString(R.string.vuln_notifications_enabled_pref_key),
        context.getResources().getBoolean(R.bool.vuln_notifications_enabled_pref_default_value))) {
      // Notifications disabled for all apps
      return false;
    }

    // Notification is permitted unless it's muted for all packages in packageNames.
    SharedPreferences mutePreferences = getMutePreferences(context);
    for (String packageName : packageNames) {
      Set<String> mutedVulnerabilityTypes =
          mutePreferences.getStringSet(packageName, Collections.<String>emptySet());
      if (!mutedVulnerabilityTypes.contains(vulnerabilityType)) {
        // Not muted for this package
        return true;
      }
    }

    return false;
  }

  private static SharedPreferences getMutePreferences(Context context) {
    return context.getSharedPreferences("mutedVulnerabilities", 0);
  }

  private static void sortVulnNotificationTypes(String[] vulnNotificationTypes) {
    Arrays.sort(vulnNotificationTypes);
  }

  static String[] getVulnNotificationLabels(Context context, String[] vulnNotificationTypes) {
    String[] labels = new String[vulnNotificationTypes.length];
    for (int i = 0; i < vulnNotificationTypes.length; i++) {
      labels[i] = getVulnerabilityTitle(context, vulnNotificationTypes[i]);
    }
    return labels;
  }

  private void showMutedVulnsForPackageDialog(
      final String packageName, final Preference preference) {
    final Context context = preference.getContext();
    PackageManager packageManager = context.getPackageManager();
    String applicationLabel = packageName;
    Drawable applicationIcon = null;
    try {
      ApplicationInfo applicationInfo = packageManager.getApplicationInfo(packageName, 0);
      CharSequence applicationLabelCharSequence =
          packageManager.getApplicationLabel(applicationInfo);
      if (applicationLabelCharSequence != null) {
        applicationLabel = applicationLabelCharSequence.toString();
      }
      applicationIcon = packageManager.getApplicationIcon(applicationInfo);
    } catch (PackageManager.NameNotFoundException ignored) {}

    final Set<String> originalMutedVulnTypes =
        getMutedNotificationsForPackage(context, packageName);
    final Set<String> mutedVulnTypes = new HashSet<String>(originalMutedVulnTypes);

    final String[] mutedVulnTypesArray = mutedVulnTypes.toArray(new String[mutedVulnTypes.size()]);
    sortVulnNotificationTypes(mutedVulnTypesArray);
    String[] mutedVulnTypesLabels =
        NotificationsPreferenceFragment.getVulnNotificationLabels(context, mutedVulnTypesArray);
    boolean[] mutedVulnTypesChecked = new boolean[mutedVulnTypesLabels.length];
    for (int i = 0; i < mutedVulnTypesChecked.length; i++) {
      mutedVulnTypesChecked[i] = true;
    }

    AlertDialog.Builder builder = new AlertDialog.Builder(context)
        .setTitle(getString(R.string.muted_vulns_dialog_title, applicationLabel))
        .setIcon(applicationIcon)
        .setMultiChoiceItems(
            mutedVulnTypesLabels,
            mutedVulnTypesChecked,
            new DialogInterface.OnMultiChoiceClickListener() {
              @Override
              public void onClick(DialogInterface dialog, int which, boolean checked) {
                String vulnType = mutedVulnTypesArray[which];
                if (checked) {
                  mutedVulnTypes.add(vulnType);
                } else {
                  mutedVulnTypes.remove(vulnType);
                }
              }
            })
        .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
          @Override
          public void onClick(DialogInterface dialog, int which) {
            if (!originalMutedVulnTypes.equals(mutedVulnTypes)) {
              setMutedNotificationsForPackage(context, packageName, mutedVulnTypes);
              if (mutedVulnTypes.isEmpty()) {
                mMutedAppsPreferenceCategory.removePreference(preference);
              }
            }
          }
        })
        .setNegativeButton(android.R.string.cancel, null);
    builder.create().show();
  }

  private static String getVulnerabilityTitle(Context context, String vulnType) {
    int resId = context.getResources().getIdentifier(
        "vuln_" + vulnType, "string", context.getPackageName());
    if (resId == 0) {
      return vulnType;
    }
    return context.getString(resId);
  }

  private static final class PackageEntryModel {
    private final String packageName;
    private final String label;
    private final Drawable icon;

    private PackageEntryModel(String packageName, String label, Drawable icon) {
      this.packageName = packageName;
      this.label = label;
      this.icon = icon;
    }
  }

  private static class PackageEntryModelByLabelComparator implements Comparator<PackageEntryModel> {
    @Override
    public int compare(PackageEntryModel lhs, PackageEntryModel rhs) {
      String name1 = lhs.label;
      String name2 = rhs.label;
      return name1.compareToIgnoreCase(name2);
    }
  }
}
