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
import android.os.Bundle;
import android.preference.CheckBoxPreference;
import android.preference.ListPreference;
import android.preference.PreferenceCategory;
import android.preference.PreferenceFragment;
import android.preference.PreferenceManager;
import android.text.TextUtils;

import java.util.Arrays;
import java.util.HashSet;

import java.io.IOException;
import java.util.Set;
import com.google.android.gms.ads.identifier.AdvertisingIdClient;
import com.google.android.gms.ads.identifier.AdvertisingIdClient.Info;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;

import android.location.Criteria;
import android.location.Location;
import android.location.LocationManager;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.provider.Settings.Secure;
import android.telephony.TelephonyManager;

/**
 * {@link PreferenceFragment} with preferences about attacks performed by the MiTM.
 */
public class AttacksPreferenceFragment extends PreferenceFragment {

  private static final Set<String> BUNDLED_SUPPORTED_ATTACK_IDS = new HashSet<String>();
  private static final Set<String> BUNDLED_SUPPORTED_DATA_ATTACK_IDS = new HashSet<String>();
  static {
    BUNDLED_SUPPORTED_ATTACK_IDS.add("clientheartbleed");
    BUNDLED_SUPPORTED_ATTACK_IDS.add("earlyccs");
    BUNDLED_SUPPORTED_ATTACK_IDS.add("dropssl");
    BUNDLED_SUPPORTED_ATTACK_IDS.add("invalidhostname");
    BUNDLED_SUPPORTED_ATTACK_IDS.add("selfsigned");

    BUNDLED_SUPPORTED_DATA_ATTACK_IDS.add("blockhttp");
    BUNDLED_SUPPORTED_DATA_ATTACK_IDS.add("httpauthdetection");
    BUNDLED_SUPPORTED_DATA_ATTACK_IDS.add("httpdetection");
    BUNDLED_SUPPORTED_DATA_ATTACK_IDS.add("imagereplace");
    BUNDLED_SUPPORTED_DATA_ATTACK_IDS.add("sslstrip");

    BUNDLED_SUPPORTED_DATA_ATTACK_IDS.add("httppii");
  }

  private static final String ATTACK_ENABLED_PREF_KEY_PREFIX = "attack_enabled_";
  private static final String SUPPORTED_ATTACKS_PREF_KEY = "supported_attacks";
  private static final String DATA_ATTACK_ENABLED_PREF_KEY_PREFIX = "data_attack_enabled_";
  private static final String SUPPORTED_DATA_ATTACKS_PREF_KEY = "supported_data_attacks";

  private ListPreference mAttackProbabilityPreference;
  private PreferenceCategory mTlsAttacksSetPreferenceCategory;
  private PreferenceCategory mOtherAttacksSetPreferenceCategory;

  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    addPreferencesFromResource(R.xml.attacks_settings);

    int attackProbabilityEntryIndex = getAttackProbabilityEntryIndex(getActivity());
    mAttackProbabilityPreference =
        (ListPreference) findPreference(getString(R.string.attack_probability_pref_key));
    mAttackProbabilityPreference.setValue(
        String.valueOf(mAttackProbabilityPreference.getEntryValues()[attackProbabilityEntryIndex]));

    mTlsAttacksSetPreferenceCategory =
        (PreferenceCategory) findPreference(getString(R.string.tls_attacks_set_pref_category_key));
    String[] supportedAttackIds = getSupportedAttackIds(getActivity()).toArray(new String[0]);
    Arrays.sort(supportedAttackIds);
    for (String attackId : supportedAttackIds) {
      CheckBoxPreference attackEnabledPreference =
          new CheckBoxPreference(mAttackProbabilityPreference.getContext());
      attackEnabledPreference.setTitle(getAttackTitle(getActivity(), attackId));
      attackEnabledPreference.setSummary(getAttackSummary(getActivity(), attackId));
      attackEnabledPreference.setKey(getAttackEnabledPreferenceKey(attackId));
      mTlsAttacksSetPreferenceCategory.addPreference(attackEnabledPreference);
    }

    mOtherAttacksSetPreferenceCategory =
        (PreferenceCategory) findPreference(
            getString(R.string.other_attacks_set_pref_category_key));
    String[] supportedDataAttackIds =
        getSupportedDataAttackIds(getActivity()).toArray(new String[0]);
    Arrays.sort(supportedDataAttackIds);
    for (String attackId : supportedDataAttackIds) {
      CheckBoxPreference attackEnabledPreference =
          new CheckBoxPreference(mAttackProbabilityPreference.getContext());
      attackEnabledPreference.setTitle(getAttackTitle(getActivity(), attackId));
      attackEnabledPreference.setSummary(getAttackSummary(getActivity(), attackId));
      attackEnabledPreference.setKey(getDataAttackEnabledPreferenceKey(attackId));
      mOtherAttacksSetPreferenceCategory.addPreference(attackEnabledPreference);
    }
  }

  private static int getAttackProbabilityEntryIndex(Context context) {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
    String defaultValue = context.getString(R.string.attack_probability_pref_default_value);
    String value = preferences.getString(
        context.getString(R.string.attack_probability_pref_key), defaultValue);
    String[] permittedValues =
        context.getResources().getStringArray(R.array.attack_probability_pref_entryValues);
    int result = Utils.indexOf(permittedValues, value);
    return (result != -1) ? result : Utils.indexOf(permittedValues, defaultValue);
  }

  /**
   * Gets the requested attack probability from preferences.
   *
   * @return probability or {@code null} for default.
   */
  public static Double getAttackProbability(Context context) {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
    String defaultValue = context.getString(R.string.attack_probability_pref_default_value);
    String value = preferences.getString(
        context.getString(R.string.attack_probability_pref_key), defaultValue);
    if (TextUtils.isEmpty(value)) {
      return null;
    }
    try {
      double p = Integer.parseInt(value) / 100.0;
      if (p < 0) {
        p = 0;
      } else if (p > 1) {
        p = 1;
      }
      return p;
    } catch (NumberFormatException e) {
      return null;
    }
  }

  private static Set<String> getSupportedAttackIds(Context context) {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
    Set<String> result = new HashSet<String>(
        preferences.getStringSet(SUPPORTED_ATTACKS_PREF_KEY, BUNDLED_SUPPORTED_ATTACK_IDS));
    return result;
  }

  public static void setSupportedAttackIds(Context context, Set<String> attackIds) {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
    SharedPreferences.Editor editor = preferences.edit();
    if (attackIds != null) {
      editor.putStringSet(SUPPORTED_ATTACKS_PREF_KEY, attackIds);
    } else {
      editor.remove(SUPPORTED_ATTACKS_PREF_KEY);
    }
    editor.apply();
  }

  /**
   * Gets the set of enabled attacks.
   *
   * @return attacks or {@code null} for default.
   */
  public static Set<String> getEnabledAttackIds(Context context) {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
    if (!preferences.getBoolean(
        context.getString(R.string.attacks_use_custom_set_pref_key),
        context.getResources().getBoolean(R.bool.attacks_use_custom_set_pref_default_value))) {
      return null;
    }
    Set<String> enabledAttackIds = new HashSet<String>();
    for (String attackId : getSupportedAttackIds(context)) {
      if (preferences.getBoolean(getAttackEnabledPreferenceKey(attackId), false)) {
        enabledAttackIds.add(attackId);
      }
    }
    return enabledAttackIds;
  }

  private static String getAttackEnabledPreferenceKey(String attackId) {
    return ATTACK_ENABLED_PREF_KEY_PREFIX + attackId;
  }

  private static Set<String> getSupportedDataAttackIds(Context context) {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
    Set<String> result = new HashSet<String>(
        preferences.getStringSet(
            SUPPORTED_DATA_ATTACKS_PREF_KEY, BUNDLED_SUPPORTED_DATA_ATTACK_IDS));
    return result;
  }

  public static void setSupportedDataAttackIds(Context context, Set<String> attackIds) {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
    SharedPreferences.Editor editor = preferences.edit();
    if (attackIds != null) {
      editor.putStringSet(SUPPORTED_DATA_ATTACKS_PREF_KEY, attackIds);
    } else {
      editor.remove(SUPPORTED_DATA_ATTACKS_PREF_KEY);
    }
    editor.apply();
  }

  /**
   * Gets the set of enabled data attacks.
   *
   * @return attacks or {@code null} for default.
   */
  public static Set<String> getEnabledDataAttackIds(Context context) {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
    if (!preferences.getBoolean(
        context.getString(R.string.attacks_use_custom_set_pref_key),
        context.getResources().getBoolean(R.bool.attacks_use_custom_set_pref_default_value))) {
      return null;
    }
    Set<String> enabledAttackIds = new HashSet<String>();
    for (String attackId : getSupportedDataAttackIds(context)) {
      if (preferences.getBoolean(getDataAttackEnabledPreferenceKey(attackId), false)) {
        enabledAttackIds.add(attackId);
      }
    }
    return enabledAttackIds;
  }

  private static String getDataAttackEnabledPreferenceKey(String attackId) {
    return DATA_ATTACK_ENABLED_PREF_KEY_PREFIX + attackId;
  }

  private static String getAttackTitle(Context context, String attackId) {
    int resId = context.getResources().getIdentifier(
        "attack_title_" + attackId, "string", context.getPackageName());
    if (resId == 0) {
      return attackId;
    }
    return context.getString(resId);
  }

  private static String getAttackSummary(Context context, String attackId) {
    int resId = context.getResources().getIdentifier(
        "attack_summary_" + attackId, "string", context.getPackageName());
    if (resId == 0) {
      return attackId;
    }
    return context.getString(resId);
  }

  public static boolean isReconnectRequiredToApplyPreference(
      @SuppressWarnings("unused") Context context, String key) {
    if (key == null) {
      return false;
    }
    if ((key.startsWith("attack_")) || (key.startsWith("attacks_")
        || (key.startsWith("data_attack_")))) {
      return true;
    }
    return false;
  }

  /**
   * Gets the set of client personal and device ids.
   *
   * @returns personal items or {@code null} for default.
   */
  public static Set<String> getPersonalItems(Context context) {
    Set<String> clientPersonalItems = new HashSet<String>();

    String android_id = getAndroidId(context);
    Info advertising_info = getAdvertisingId(context);
    String device_id = getDeviceId(context);
    String mac_address = getMACAddress(context);

    if (android_id != null) {
        clientPersonalItems.add("'android_id':'" + android_id + "'");
    }
    if (advertising_info != null) {
        clientPersonalItems.add("'google_advertising_id':'" + advertising_info.getId() + "'");
    }
    if (device_id != null) {
        clientPersonalItems.add("'device_id':'" + device_id + "'");
     }
    if (mac_address != null) {
        clientPersonalItems.add("'mac_address':'" + mac_address + "'");
    }
    return clientPersonalItems;
  }

  /**
   * Gets the device's current location.
   *
   * @returns device location or {@code null} if not available.
   */
  public static Set<String> getDeviceLocation(Context context) {
    Set<String> clientDeviceLocation = new HashSet<String>();

    Location device_location;
    try {
        LocationManager location_manager =
          (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);

        Criteria criteria = new Criteria();
        criteria.setAccuracy(Criteria.ACCURACY_FINE);
        String location_provider = location_manager.getBestProvider(criteria, false);
        device_location = location_manager.getLastKnownLocation(location_provider);
    }
    catch (Exception e) {
        device_location = null;
    }
    if (device_location != null) {
        String latitude = String.valueOf(device_location.getLatitude());
        String longitude = String.valueOf(device_location.getLongitude());

        clientDeviceLocation.add("'latitude':'" + latitude + "', " +
            "'longitude':'" + longitude + "'");
    }
    return clientDeviceLocation;
  }

  /*
   * Gets the device's Android ID.
   *
   * @returns the device's Android ID or {@code null} if not available.
   */
  private static String getAndroidId(Context context) {
    return Secure.getString(context.getContentResolver(), Secure.ANDROID_ID);
  }

  /*
   * Gets the user's Advertising ID.
   *
   * @returns the Advertising ID or {@code null} if not available.
   */
  private static Info getAdvertisingId(Context context) {
    Info advertising_info;
    try {
        advertising_info = AdvertisingIdClient.getAdvertisingIdInfo(context);
        /**
         * TODO: Include check to alert when device user has enabled "Limit Ad Tracking"
         *       for their Google account. This will allow testers to verify apps sending the
         *       user's "Android ID" to advertisers when they shouldn't.
         */
         //final boolean ad_tracking_limited = advertising_info.isLimitAdTrackingEnabled();
    }
    catch (GooglePlayServicesRepairableException | GooglePlayServicesNotAvailableException |
           IOException e) {
        /** Encountered a recoverable error connecting to Google Play services OR
          *  Google Play services is not available entirely OR
          * a general IO exception.
          */
        advertising_info = null;
    }
    return advertising_info;
  }

  /*
   * Gets the device's Device ID.
   *
   * @returns the Device ID or {@code null} if not available.
   */
  private static String getDeviceId(Context context) {
    //Retrieve a reference to an instance of TelephonyManager
    TelephonyManager telephonyManager =
              (TelephonyManager)context.getSystemService(Context.TELEPHONY_SERVICE);
    // Fetch the device's unique ID if it exists.
    // Note. This varies depending on network e.g. IMEI for GSM, MEID/ESN for CDMA.
    String device_id = telephonyManager.getDeviceId();
    if (device_id == null){
          return null;
    }
    else {
          return device_id;
    }
  }

  /*
   * Gets the device's MAC Address.
   *
   * @returns the MAC Address or {@code null} if not available.
   */
  private static String getMACAddress (Context context) {
    WifiManager wifi_manager = (WifiManager)context.getSystemService(Context.WIFI_SERVICE);
    WifiInfo wifi_info = wifi_manager.getConnectionInfo();

    // Fetch the device's WiFi MAC address.
    String mac_address = wifi_info.getMacAddress();
    if (mac_address == null) {
          return null;
    }
    else {
          return mac_address;
    }
  }

  /*
   * Gets the device's location i.e. longitude and latitude.
   *
   * @returns the location or {@code null} if not available.
   */
  /*
  private static Location getDeviceLocation (Context context) {
    Location last_known_location;
    try {
        LocationManager location_manager =
        (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);

        Criteria criteria = new Criteria();
        criteria.setAccuracy(Criteria.ACCURACY_FINE);
        String location_provider = location_manager.getBestProvider(criteria, false);
        last_known_location = location_manager.getLastKnownLocation(location_provider);
    }
    catch (Exception e) {
        last_known_location = null;
    }
    return last_known_location;
  }
  */
}
