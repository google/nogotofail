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

package net.nogotofail.mitmtester.util;

import android.content.Context;
import android.location.Criteria;
import android.location.Location;
import android.location.LocationManager;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.provider.Settings;
import android.telephony.TelephonyManager;

import com.google.android.gms.ads.identifier.AdvertisingIdClient;
import com.google.android.gms.ads.identifier.AdvertisingIdClient.Info;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;

import java.io.IOException;

 /*
 *  ClientProperties provides methods to retrieve user and device details.
 */
public class ClientProperties {

    public static String getAndroidId(Context context) {
        return Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
    }

    public static Info getAdvertisingId(Context context) {
        Info advertising_info;
        try {
            advertising_info = AdvertisingIdClient.getAdvertisingIdInfo(context);
            /**
             * TODO: Include check to alert when device user has enabled "Limit Ad Tracking"
             *       for their Google account. This will allow testers to verify apps sending the
             *       user's "Android ID" to advertisers when they shouldn't.
             */
            //final boolean ad_tracking_limited = advertising_info.isLimitAdTrackingEnabled();
        } catch (GooglePlayServicesRepairableException | GooglePlayServicesNotAvailableException |
                 IOException e) {
            /** Encountered a recoverable error connecting to Google Play services OR
             *  Google Play services is not available entirely OR
             * a general IO exception.
             */
            advertising_info = null;
        }
        return advertising_info;
    }

    public static String getDeviceId(Context context) {
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

    public static String getMacAddress (Context context) {
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

    public static Location getDeviceLocation (Context context) {
        Location last_known_location = null;
        try {
            LocationManager location_manager =
                    (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);

            Criteria criteria = new Criteria();
            criteria.setAccuracy(Criteria.ACCURACY_FINE);
            String location_provider = location_manager.getBestProvider(criteria, false);
            last_known_location = location_manager.getLastKnownLocation(location_provider);
        }
        catch (Exception e) {

        }
        return last_known_location;
    }
}
