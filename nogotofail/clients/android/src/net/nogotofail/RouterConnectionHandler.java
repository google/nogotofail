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
import android.os.Build;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Log;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Protocol handler for the connection to the MiTM server.
 *
 * <p>The protocol is line-oriented.
 *
 * <p>The handshake is similar to HTTP response/request without body. The client sends:
 * <pre>
 *   nogotofail_ctl/1.0
 *   User-Agent: ...
 *   Platform-Info: ...
 *   ...
 * </pre>
 * followed by an empty line. The server replies with status code ({@code 0} for success) and
 * status message, followed by headers, followed by an empty line.
 *
 * <p>The server can then send commands to the client. Each command starts with a transaction ID,
 * an opaque (to client) string, followed by a space, followed by the name of the command, followed
 * optionally followed by space and additional arguments. The client responds with the transaction
 * ID corresponding to a request, followed by space, followed by the return value for that request.
 *
 * <p>Supported commands:
 * <ul>
 * <li>{@code tcp_client_id src_port [dst_ip_addr_in_hex [dsp_port]]} -- looks up a process that
 *     is responsible for the outbound TCP connection matching the parameters and returns the
 *     ID of the package(s) associated with the process. The list of packages is comma-separated,
 *     with each entry consisting of package name followed by space followed by version code.
 * </li>
 * <li>{@code vuln_notify request_id vuln_type dst_host/addr dst_port [<pkg name> <version code>[, ...]]]}
 *     -- notifies the user of this Android that network traffic is vulnerable. The list of packages
 *     is comma-separated, with each entry consisting of package name followed by space followed by
 *     version code.
 * </li>
 * </ul>
 */
public class RouterConnectionHandler implements RouterSocketClient.ConnectionHandler {

  /**
   * Handler of a command received from the server.
   */
  interface CommandHandler {
    String handleCommand(InetAddress localAddress, String parameters) throws IOException;
  }

  private static final String TAG = RouterConnectionHandler.class.getSimpleName();

  private static final String PROTOCOL_NAME = "nogotofail_ctl";
  private static final String PROTOCOL_VERSION = "1.0";
  private static final String HEADER_USER_AGENT = "User-Agent";
  private static final String HEADER_PLATFORM_INFO = "Platform-Info";
  private static final String HEADER_INSTALLATION_ID = "Installation-ID";
  private static final String HEADER_ATTACK_PROBABILITY = "Attack-Probability";
  private static final String HEADER_ENABLED_ATTACKS = "Attacks";
  private static final String HEADER_SUPPORTED_ATTACKS = "Supported-Attacks";
  private static final String HEADER_SUPPORTED_ATTACKS_LOWER_CASE =
      HEADER_SUPPORTED_ATTACKS.toLowerCase(Locale.US);
  private static final String HEADER_ENABLED_DATA_ATTACKS = "Data-Attacks";
  private static final String HEADER_SUPPORTED_DATA_ATTACKS = "Supported-Data-Attacks";
  private static final String HEADER_SUPPORTED_DATA_ATTACKS_LOWER_CASE =
      HEADER_SUPPORTED_DATA_ATTACKS.toLowerCase(Locale.US);

  /**
   * Timeout (milliseconds) for a read operation waiting for a command from the server. The server
   * may send commands very infrequently. The timeout is thus set to a large enough value to avoid
   * cycling too much when waiting for a command from the server.
   */
  private static final long INTERCOMMAND_READ_TIMEOUT_MILLIS = TimeUnit.MINUTES.toMillis(5);

  /** Timeout (milliseconds) after which to terminate the connection and initiate a retry if no data
   * has been received over the connection. */
  private static final long CONNECTION_IDLE_TIMEOUT_MILLIS = TimeUnit.MINUTES.toMillis(30);

  private final Context mContext;
  private final String mPlatformInfo;
  private final String mUserAgent;
  private final Map<String, CommandHandler> mCommandHandlers =
      new HashMap<String, CommandHandler>();


  public RouterConnectionHandler(Context context) {
    mContext = context;
    String packageName = context.getPackageName();
    PackageInfo packageInfo;
    try {
      packageInfo = context.getPackageManager().getPackageInfo(packageName, 0);
    } catch (PackageManager.NameNotFoundException e) {
      packageInfo = null;
    }
    int versionCode = (packageInfo != null) ? packageInfo.versionCode : -1;
    mUserAgent = packageName + "/" + versionCode
        + " (Linux"
        + "; Android " + Build.VERSION.RELEASE + ")";
    mPlatformInfo = Build.FINGERPRINT;

    mCommandHandlers.put("tcp_client_id", new TcpClientInfoCommandHandler(context));
    mCommandHandlers.put("vuln_notify", new VulnNotifyCommandHandler(context));
  }

  @Override
  public void handleConnection(Socket socket) throws IOException {
    Log.i(TAG, "Handling connection to " + socket.getRemoteSocketAddress());
    try {
      BufferedWriter out =
          new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"));
      BufferedReader in =
          new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));

      // Start handshake
      writeHandshakeRequestLine(out, PROTOCOL_NAME + "/" + PROTOCOL_VERSION);
      writeHandshakeRequestHeader(out, HEADER_USER_AGENT, mUserAgent);
      writeHandshakeRequestHeader(
          out, HEADER_INSTALLATION_ID, AdvancedPreferenceFragment.getInstallationId(mContext));
      writeHandshakeRequestHeader(out, HEADER_PLATFORM_INFO, mPlatformInfo);
      Double requestedAttackProbability =
          AttacksPreferenceFragment.getAttackProbability(mContext);
      if (requestedAttackProbability != null) {
        writeHandshakeRequestHeader(
            out, HEADER_ATTACK_PROBABILITY, String.valueOf(requestedAttackProbability));
      }
      Set<String> requestedEnabledAttackIds =
          AttacksPreferenceFragment.getEnabledAttackIds(mContext);
      if (requestedEnabledAttackIds != null) {
        writeHandshakeRequestHeader(
            out, HEADER_ENABLED_ATTACKS, TextUtils.join(",", requestedEnabledAttackIds));
      }
      Set<String> requestedEnabledDataAttackIds =
          AttacksPreferenceFragment.getEnabledDataAttackIds(mContext);
      if (requestedEnabledDataAttackIds != null) {
        writeHandshakeRequestHeader(
            out, HEADER_ENABLED_DATA_ATTACKS, TextUtils.join(",", requestedEnabledDataAttackIds));
      }
      out.write("\r\n");
      out.flush();

      boolean responseRead = false;
      boolean firstLineRead = false;
      String line;
      while ((line = in.readLine()) != null) {
        if (line.length() == 0) {
          // End of response
          responseRead = true;
          break;
        }
        Log.d(TAG, "Handshake response line: " + line);
        if (!firstLineRead) {
          // Status line
          String[] tokens = line.split("\\s", 2);
          String responseCode = tokens[0];
          if (!"0".equals(responseCode)) {
            throw new IOException("Handshake failed. Server reply: " + line);
          }
          firstLineRead = true;
          continue;
        }
        // Header line
        int delimiterIndex = line.indexOf(':');
        String headerName;
        String headerValue;
        if (delimiterIndex != -1) {
          headerName = line.substring(0, delimiterIndex).trim();
          headerValue = line.substring(delimiterIndex + 1).trim();
        } else {
          headerName = line.trim();
          headerValue = null;
        }
        String headerNameLowerCase = headerName.toLowerCase(Locale.US);
        if (HEADER_SUPPORTED_ATTACKS_LOWER_CASE.equals(headerNameLowerCase)) {
          String[] attackIdsArray = (headerValue != null) ? headerValue.split(",") : new String[0];
          Set<String> attackIds = new HashSet<String>();
          for (String attackId : attackIdsArray) {
            attackId = attackId.trim();
            if (!attackId.isEmpty()) {
              attackIds.add(attackId);
            }
          }
          AttacksPreferenceFragment.setSupportedAttackIds(mContext, attackIds);
        } else if (HEADER_SUPPORTED_DATA_ATTACKS_LOWER_CASE.equals(headerNameLowerCase)) {
          String[] attackIdsArray = (headerValue != null) ? headerValue.split(",") : new String[0];
          Set<String> attackIds = new HashSet<String>();
          for (String attackId : attackIdsArray) {
            attackId = attackId.trim();
            if (!attackId.isEmpty()) {
              attackIds.add(attackId);
            }
          }
          AttacksPreferenceFragment.setSupportedDataAttackIds(mContext, attackIds);
        }
      }
      if (!firstLineRead) {
        throw new EOFException("Empty response to handshake");
      }
      if (!responseRead) {
        throw new EOFException("Premature EOF while reading handshake response");
      }

      // Handshake completed
      Log.d(TAG, "Handshake succeeded");

      // IMPLEMENTATION NOTE: The timeout below technically affects not just the first read of a new
      // command, but also any reads while already reading a command. It's pretty much impossible to
      // use different timeouts for these two operations while using a stock BufferedReader. It
      // should be possible to use two different timeouts if we switch to a binary (rather than
      // line-oriented) format or if we create our own BufferedInputStream reader.
      // TODO: Switch to using a much shorter read timeout while already reading a command.
      socket.setSoTimeout((int) INTERCOMMAND_READ_TIMEOUT_MILLIS);
      long lastReceivedDataTimestampMillis = SystemClock.elapsedRealtime();
      while (true) {
        try {
          while ((line = in.readLine()) != null) {
            // Received a request from the server
            lastReceivedDataTimestampMillis = SystemClock.elapsedRealtime();
            int transactionIdDelimiterIndex = line.indexOf(' ');
            if (transactionIdDelimiterIndex == -1) {
              throw new IOException("No transaction ID in request");
            }
            if (Log.isLoggable(TAG, Log.VERBOSE)) {
              Log.v(TAG, "Request: " + line);
            }
            String transactionId = line.substring(0, transactionIdDelimiterIndex);
            line = line.substring(transactionIdDelimiterIndex + 1);
            int commandDelimiterIndex = line.indexOf(' ');
            String command;
            if (commandDelimiterIndex == -1) {
              command = line;
              line = "";
            } else {
              command = line.substring(0, commandDelimiterIndex);
              line = line.substring(commandDelimiterIndex + 1);
            }

            String replyPayload;
            CommandHandler commandHandler = mCommandHandlers.get(command);
            if (commandHandler != null) {
              replyPayload = commandHandler.handleCommand(socket.getLocalAddress(), line);
              if (replyPayload == null) {
                replyPayload = "";
              }
            } else {
              replyPayload = "ERROR: Unsupported command";
            }
            if (Log.isLoggable(TAG, Log.VERBOSE)) {
              Log.v(TAG, "Reply: " + transactionId + " " + replyPayload);
            }
            out.write(transactionId + " " + replyPayload + "\n");
            out.flush();
          }
          Log.d(TAG, "EOF from server");
          return;
        } catch (SocketTimeoutException ignored) {
          // Read timed out
          Log.v(TAG, "Socket timed out");
          long idleTimeMillis = SystemClock.elapsedRealtime() - lastReceivedDataTimestampMillis;
          if (idleTimeMillis >= CONNECTION_IDLE_TIMEOUT_MILLIS) {
            // Connection idle for too long -- terminate the connection and initiate a retry.
            throw new IOException("Connection idle for too long: "
                + (idleTimeMillis / 1000) + " seconds");
          }
          // Try reading again
        }
      }
    } finally {
      Log.i(TAG, "DONE handling connection to " + socket.getRemoteSocketAddress());
    }
  }

  private static void writeHandshakeRequestHeader(
      BufferedWriter out, String headerName, String headerValue) throws IOException {
    boolean valueCensored = false;
    if (HEADER_INSTALLATION_ID.equals(headerName)) {
      valueCensored = true;
    }

    if (valueCensored) {
      Log.d(TAG, "Sending handshake request line: " + headerName + ": <REDACTED>");
      out.write(headerName + ": " + headerValue + "\r\n");
    } else {
      writeHandshakeRequestLine(out, headerName + ": " + headerValue);
    }
  }

  private static void writeHandshakeRequestLine(
      BufferedWriter out, String line) throws IOException {
    Log.d(TAG, "Sending handshake request line: " + line);
    out.write(line + "\r\n");
  }
}
