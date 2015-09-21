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
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Log;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Handler of TCP client info commands from the MiTM server.
 */
public class TcpClientInfoCommandHandler implements RouterConnectionHandler.CommandHandler {
  private static final String TAG = TcpClientInfoCommandHandler.class.getSimpleName();

  private final Context mContext;

  public TcpClientInfoCommandHandler(Context context) {
    mContext = context;
  }

  @Override
  public String handleCommand(
      InetAddress localAddress, String parameters) throws IOException {
    // Request:
    //   <source port> [<dest IP address> [<dest port>]]
    String[] tokens = parameters.split("\\s");
    int sourcePort = Integer.parseInt(tokens[0]);
    byte[] destinationIp = (tokens.length > 1) ? HexEncoding.decode(tokens[1]) : null;
    int destinationPort = (tokens.length > 2) ? Integer.parseInt(tokens[2]) : -1;

    byte[] sourceIp = localAddress.getAddress();
    long timeBefore = System.currentTimeMillis();
    Integer uid = getUidForConnection(sourceIp, sourcePort, destinationIp, destinationPort);
    long timeAfter = System.currentTimeMillis();
    Log.i(TAG, "TCP Client Info looked up in " + (timeAfter - timeBefore) + " ms");
    if (uid == null) {
      Log.w(TAG, "Failed to look up: " + parameters);
      return "";
    }

    String info = null;
    try {
      info = getAppInfoForUid(mContext, uid);
    } catch (PackageManager.NameNotFoundException ignored) {
      Log.w(TAG, "Failed to look up package info for UID " + uid);
    }
    return info;
  }

  private static Integer getUidForConnection(
      byte[] sourceIp, int sourcePort, byte[] destinationIp, int destinationPort) {

    // Convert the IP address to the format used by /proc/net/tcp and /proc/net/tcp6
    if (sourceIp != null) {
      try {
        sourceIp = inetAddressNetworkToProcOrder(sourceIp);
      } catch (IllegalArgumentException e) {
        Log.w(TAG, "Invalid source IP: " + HexEncoding.encode(sourceIp));
        return null;
      }
    }
    if (destinationIp != null) {
      try {
        destinationIp = inetAddressNetworkToProcOrder(destinationIp);
      } catch (IllegalArgumentException e) {
        Log.w(TAG, "Invalid destination IP: " + HexEncoding.encode(destinationIp));
        return null;
      }
    }

    // Try IPv6 first followed by IPv4.
    String[][] procNetTcp6 = null;
    try {
      procNetTcp6 = readProcNetTcp(new File("/proc/net/tcp6"));
    } catch (IOException e) {
      Log.w(TAG, "Failed to load IPv6 TCP info", e);
    }
    if (procNetTcp6 != null) {
      Integer uid = getUidForConnection(
          procNetTcp6, sourceIp, sourcePort, destinationIp, destinationPort);
      if (uid != null) {
        return uid;
      }
    }

    // Addresses longer than 4 bytes can't match anything in IPv4 table.
    boolean needCheckIpv4Table =
        ((sourceIp == null) || (sourceIp.length <= 4))
        && ((destinationIp == null) || (destinationIp.length <= 4));
    String[][] procNetTcp4 = null;
    if (needCheckIpv4Table) {
      try {
        procNetTcp4 = readProcNetTcp(new File("/proc/net/tcp"));
      } catch (IOException e) {
        Log.w(TAG, "Failed to load IPv4 TCP info", e);
      }
      if (procNetTcp4 != null) {
        Integer uid = getUidForConnection(
            procNetTcp4, sourceIp, sourcePort, destinationIp, destinationPort);
        if (uid != null) {
          return uid;
        }
      }
    }

    // No exact match found -- try without matching the source IP because when an Android is on a
    // VPNs the source IP may be different (WLAN address instead of VPN address) but source port
    // (luckily) appears to stay the same.
    if (sourceIp == null) {
      // Source IP wasn't being matched anyway
      return null;
    }
    if (procNetTcp6 != null) {
      Integer uid = getUidForConnection(
          procNetTcp6, null, sourcePort, destinationIp, destinationPort);
      if (uid != null) {
        return uid;
      }
    }

    // Addresses longer than 4 bytes can't match anything in IPv4 table.
    needCheckIpv4Table = ((destinationIp == null) || (destinationIp.length <= 4));
    if (needCheckIpv4Table) {
      if (procNetTcp4 == null) {
        try {
          procNetTcp4 = readProcNetTcp(new File("/proc/net/tcp"));
        } catch (IOException e) {
          Log.w(TAG, "Failed to load IPv4 TCP info", e);
        }
      }
      if (procNetTcp4 != null) {
        Integer uid = getUidForConnection(
            procNetTcp4, null, sourcePort, destinationIp, destinationPort);
        if (uid != null) {
          return uid;
        }
      }
    }

    return null;
  }

  private static String getAppInfoForUid(Context context, int uid)
      throws PackageManager.NameNotFoundException {
    PackageManager packageManager = context.getPackageManager();
    String[] packageNames = packageManager.getPackagesForUid(uid);
    if ((packageNames == null) || (packageNames.length == 0)) {
      throw new PackageManager.NameNotFoundException("uid: " + uid);
    }

    StringBuilder result = new StringBuilder();
    for (String packageName : packageNames) {
      if (result.length() > 0) {
        result.append(", ");
      }
      PackageInfo packageInfo = packageManager.getPackageInfo(packageName, 0);
      result.append(packageInfo.packageName + " " + packageInfo.versionCode);
    }
    return result.toString();
  }

  private static Integer getUidForConnection(String[][] procNetTcpLines,
      byte[] sourceIpInProcFormat, int sourcePort,
      byte[] destinationIpInProcFormat, int destinationPort) {
    Log.d(TAG, "Looking up: "
      + ((sourceIpInProcFormat != null) ? HexEncoding.encode(sourceIpInProcFormat) : "any")
        + ":" + ((sourcePort >= 0) ? Integer.toHexString(sourcePort) : "any")
        + " " + ((destinationIpInProcFormat != null)
            ? HexEncoding.encode(destinationIpInProcFormat) : "any")
        + ":" + ((destinationPort >= 0) ? Integer.toHexString(destinationPort) : "any"));
    for (String[] fields : procNetTcpLines) {
      // Skip empty lines
      if (fields.length == 0) {
        continue;
      }
      String srcAddressAndPortText = fields[2];
      String dstAddressAndPortText = fields[3];
      String[] srcAddressAndPort = srcAddressAndPortText.split(":");
      String[] dstAddressAndPort = dstAddressAndPortText.split(":");

      // Match on ports first as it avoid parsing IP addresses if a port-based match fails
      if (sourcePort >= 0) {
        int srcPort = Integer.parseInt(srcAddressAndPort[1], 16);
        if (srcPort != sourcePort) {
          continue;
        }
      }

      if (destinationPort >= 0) {
        int dstPort = Integer.parseInt(dstAddressAndPort[1], 16);
        if (dstPort != destinationPort) {
          continue;
        }
      }

      // Match on destination IP address first because it's more likely to differ across the entries
      if (destinationIpInProcFormat != null) {
        byte[] dstIp = HexEncoding.decode(dstAddressAndPort[0]);
        if (!endsWith(dstIp, destinationIpInProcFormat)) {
          continue;
        }
      }

      if (sourceIpInProcFormat != null) {
        byte[] srcIp = HexEncoding.decode(srcAddressAndPort[0]);
        if (!endsWith(srcIp, sourceIpInProcFormat)) {
          continue;
        }
      }

      String uidText = fields[8];
      int uid = Integer.parseInt(uidText);
      return uid;
    }

    return null;
  }

  private static boolean endsWith(byte[] array, byte[] suffix) {
    if (suffix.length == 0) {
      return true;
    } else if (suffix.length > array.length) {
      return false;
    }
    for (int i = 0; i < suffix.length; i++) {
      if (array[array.length - suffix.length + i] != suffix[i]) {
        return false;
      }
    }
    return true;
  }

  private static final boolean BIG_ENDIAN_NATIVE_PLATFORM =
      ByteOrder.nativeOrder() == ByteOrder.BIG_ENDIAN;

  /**
   * Converts the provided IP address in network order to the corresponding IP address
   * representation used by {@code /proc/net/tcp} and {@code /proc/net/tcp6}.
   */
  private static byte[] inetAddressNetworkToProcOrder(byte[] input) {
    // proc/net/tcp and /proc/net/tcp6 list addresses in a weird format where 32-bit words are in
    // network order, but inside each word the bytes are in native order. This means that on
    // big-endian native platforms there's no need to modify the input, whereas on little-endian
    // native platforms we need to swap the byte order within each 32-bit word.
    if ((input.length % 4) != 0) {
      throw new IllegalArgumentException(
          "IP address size should be a multiple of four: " + input.length);
    }
    if (BIG_ENDIAN_NATIVE_PLATFORM) {
      // Big-endian native platform -- optimization: no need to modify the input
      return input;
    }

    // Little-endian native platform -- swap the byte order within each 32-bit word
    ByteBuffer in = ByteBuffer.wrap(input);
    in.order(ByteOrder.BIG_ENDIAN);
    byte[] result = new byte[input.length];
    ByteBuffer out = ByteBuffer.wrap(result);
    out.order(ByteOrder.nativeOrder());
    for (int word = 0; word < input.length / 4; word++) {
      out.putInt(in.getInt());
    }
    return result;
  }

  /**
   * Reads the contents of the {@code /proc/net/tcp} (or similar) and returns its lines (excluding
   * the header).
   */
  private static String[][] readProcNetTcp(File file) throws IOException {
    BufferedReader in = null;
    try {
      in = new BufferedReader(new InputStreamReader(new FileInputStream(file), "US-ASCII"));
      // Read and skip the header
      String line = in.readLine();
      if (line == null) {
        throw new EOFException("No header in " + file);
      }
      List<String> lines = new ArrayList<String>();
      while ((line = in.readLine()) != null) {
        // Skip empty lines
        if (line.trim().isEmpty()) {
          continue;
        }
        lines.add(line);
      }
      String[][] result = new String[lines.size()][];
      for (int i = 0; i < result.length; i++) {
        result[i] = lines.get(i).split("\\s+");
      }
      return result;
    } finally {
      Closeables.closeQuietly(in);
    }
  }
}
